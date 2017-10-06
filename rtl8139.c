#include <linux/module.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/netdevice.h> 
#include <linux/etherdevice.h>
#include <linux/kernel.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <linux/types.h>

#include "rtl_register.h"

#define REALTEK_VENDER_ID  0x10EC
#define REALTEK_DEVICE_ID   0x8139
#define DRIVER "rtl8139"
#define NUM_TX_DESC 4

static struct net_device *rtl8139_dev;

struct rtl8139_priv {
	struct pci_dev *pci_dev; /*PCI device */
	void *mmio_addr;  /*memory mapped I/O addr */
	unsigned long regs_len; /* length of I/O or MMI/O region */
	unsigned int tx_flag;  /*tx_flag shall contain transmission flags to notify the device*/
	unsigned int cur_tx;  /*cur_tx shall hold current transmission descriptor*/
	unsigned int dirty_tx; /*dirty_tx denotes the first of transmission descriptors which have not completed transmission.*/
	unsigned char *tx_buf[NUM_TX_DESC];   /* Tx bounce buffers */
	unsigned char *tx_bufs;               /* Tx bounce buffer region. */
	dma_addr_t tx_bufs_dma;
	struct net_device_stats stats;
	unsigned char *rx_ring;
	dma_addr_t rx_ring_dma;
	unsigned int cur_rx;
};
static struct pci_dev *rtl8139_probe(void){
	struct pci_dev *pdev=NULL;
	/* Look for RealTek 8139 NIC */
	/*begin or continue searching for a PCI device by vendor/device id. struct pci_dev *pci_get_device(unsigned int vendor, unsigned int device,struct pci_dev *from);*/
	pdev=pci_get_device(REALTEK_VENDER_ID,REALTEK_DEVICE_ID,NULL);
	if(pdev){
		/* device found, enable it */
		if(pci_enable_device(pdev)){                                           /*0 on success; error code otherwise */
			pr_err("PCI DEVICE: Couln't able to device\n");
			return NULL;
		}
		else
			pr_info("PCI DEVICE: Device Eanbled\n");
	}
	else{
		pr_err("REALTEK Device not found\n");
		return pdev;
	}
	return pdev;
}
static int rtl8139_init(struct pci_dev *pdev, struct net_device **dev_out){
	struct net_device *ndev;
	struct rtl8139_priv *priv;
	/* 
         * alloc_etherdev allocates memory for dev and dev->priv.
         * dev->priv shall have sizeof(struct rtl8139_private) memory
         * allocated.
         */
	ndev=alloc_etherdev(sizeof(struct rtl8139_priv)); /*alloc_etherdev(sizeof_priv)*/
	if(!ndev){
		pr_err("Couldn't allocate etherdev\n");
		return -1;
	}
	/*Get network device private data*/
	priv=netdev_priv(ndev);  /*dev_priv - access network device private data @ndev: network device */
	priv->pci_dev=pdev;   
	*dev_out=ndev;
	return 0;
}	
static void rtl8139_interrupt(int irq, void *dev_instance, struct pt_regs *regs){
	struct net_device *dev = (struct net_device*)dev_instance;
	struct rtl8139_priv *priv=netdev_priv(dev);
	void __iomem *ioaddr=priv->mmio_addr;
	unsigned short isr=readw(ioaddr + ISR);
   /* clear all interrupt.
    * Specs says reading ISR clears all interrupts and writing
    * has no effect. But this does not seem to be case. I keep on
    * getting interrupt unless I forcibly clears all interrupt :-(
    */	
    	writew(0xffff,ioaddr + ISR);
	if((isr & TxOK) || (isr & TxErr)){
		while((priv->dirty_tx != priv->cur_tx ) && netif_queue_stopped(dev)){
			unsigned int txstatus=readl(ioaddr + TSD0 + priv->dirty_tx * sizeof(int));
			/* not yet transmitted */
			if(!(txstatus & (TxStatOK |TxAborted | TxUnderrun))) break;
			if(txstatus & TxStatOK){
				pr_info("Transmit OK interrupt\n");
				priv->stats.tx_bytes += (txstatus & 0x1fff);
				priv->stats.tx_packets++;
			}
			else{
				pr_err("Transmit Error interrupt\n");
				priv->stats.tx_errors++;
			}
			priv->dirty_tx++;
			priv->dirty_tx = priv->dirty_tx % NUM_TX_DESC;
			if ((priv->dirty_tx == priv->cur_tx) & netif_queue_stopped(dev)) {
				pr_info("waking up queue\n");
				 netif_wake_queue(dev);
			}
		}
	}
	if(isr & RxErr){
		pr_err("receive err interrupt\n");
		priv->stats.rx_errors++;
	}
	if(isr & RxOK ){
		pr_info("receive interrupt received\n");
		while((readb(ioaddr + CR) & RxBufEmpty)==0){ /*We read from the receiver buffer until we have read all data.*/
			unsigned int rx_status;
			unsigned short rx_size;
			unsigned short pkt_size;
			struct sk_buff *skb;
			if(priv->cur_rx > RX_BUF_LEN){
				priv->cur_rx = priv->cur_rx % RX_BUF_LEN;
				/* Need to convert rx_status from little to host endian*/
				rx_status = *(unsigned int *)(priv->rx_ring + priv->cur_rx);
				rx_size = rx_status >> 16;
				/* first two bytes are receive status register 
				 ** and next two bytes are frame length  */
				pkt_size = rx_size - 4;
				/* hand over packet to system */
/*
 * The networking layer reserves some headroom in skb data (via
 * dev_alloc_skb). This is used to avoid having to reallocate skb data when
 * the header has to grow. In the default case, if the header has to grow
 * 32 bytes or less we avoid the reallocation.*/
/**
 *      skb_reserve - adjust headroom
 *      @skb: buffer to alter
 *      @len: bytes to move
 *
 *      Increase the headroom of an empty &sk_buff by reducing the tail
 *      room. This is only allowed for an empty buffer.
 */
				skb=dev_alloc_skb(pkt_size+2);
				if(skb){
					skb->dev=dev;
					skb_reserve (skb, 2); /* 16 byte align the IP fields */
			//		eth_copy_and_sum(skb, priv->rx_ring + priv->cur_rx + 4, pkt_size, 0);
					memcpy(skb, priv->rx_ring + priv->cur_rx + 4, pkt_size);
					skb_put(skb,pkt_size);                 //add data to a buffer 
					skb->protocol=eth_type_trans(skb,dev);
					/* netif_rx, which hands off the socket buffer to the upper layers*/
					netif_rx (skb);
					dev->last_rx = jiffies;/*You need to read the current counter whenever your code needs to calculate a future time stamp*/
					priv->stats.rx_bytes += pkt_size;
					priv->stats.rx_packets++;
				}
				else{
					pr_info("Memory squeeze, dropping packet.\n");
					priv->stats.rx_dropped++;
				}
				/* update tp->cur_rx to next writing location  */
				priv->cur_rx = (priv->cur_rx + rx_size + 4 + 3) & ~3;
				/* update CAPR((Current Address of Packet Read)) */
				writew(priv->cur_rx, ioaddr + CAPR);
			}
		}
	}
	 if(isr & CableLen) pr_err("cable length change interrupt\n");
	 if(isr & TimeOut) pr_err("time interrupt\n");
	 if(isr & SysErr) pr_err("system err interrupt\n");
	 return;
}

static void rtl8139_chip_reset (void *ioaddr){
	int i;
	/* Soft reset the chip. */
	writeb(CmdReset, ioaddr + CR);
	 /* Check that the chip has finished the reset. */
	/*the memory barrier is needed to ensure that the reset happen in the expected order.*/
	for(i=1000;i>0;i--){
		barrier();
		if((readb(ioaddr + CR) & CmdReset) == 0) break;
		udelay (10);
	}

}

static void rtl8139_init_ring(struct net_device *dev){
	struct rtl8139_priv *priv=netdev_priv(dev);
	int i;
	priv->cur_tx = 0;
	priv->dirty_tx = 0;
	for(i=0;i<NUM_TX_DESC;i++)
		priv->tx_buf[i]= &priv->tx_bufs[i * TX_BUF_SIZE];
	return; 
}
static void rtl8139_hw_start (struct net_device *dev) {
	struct rtl8139_priv *priv=netdev_priv(dev);
	void __iomem *ioaddr=priv->mmio_addr;
	u32 i;
	rtl8139_chip_reset(ioaddr);
	/* Must enable Tx/Rx before setting transfer thresholds! */
	 writeb(CmdTxEnb|CmdRxEnb, ioaddr + CR);
	 /* tx config */
	writel(0x00000600, ioaddr + TCR); /* DMA burst size 1024 */
	/* rx config */
	/*
	 *Bit 1 - Accept physical match packets
	 *Bit 2 - Accept multicast packets
	 *Bit 3 - Accept broadcast packets
	 *Bit 7 - WRAP. When set to 1, RTL8139 will keep moving the rest of packet data into the memory immediately after the end of Rx buffer.
	 *Bit 8-10 - Max DMA burst size per Rx DMA burst. We are configuring this to 111, which means unlimited.
	 *Bit 11-12 - Rx buffer length. We are configuring to 10 which means 32K+16 bytes. */
	 writel((1<<1)|(1<<2)|(1<<3)|(1<<7)|(7<<8)|(11<<3),ioaddr + RCR); 
	/* init Tx buffer DMA addresses */
	for(i=0;i<NUM_TX_DESC;i++){
		writel(priv->tx_bufs_dma+(priv->tx_buf[i]- priv->tx_bufs),ioaddr + TSAD0 + (i*4));
	}
	  /* init RBSTART */
	writel(priv->rx_ring_dma, ioaddr + RBSTART);
	/* initialize missed packet counter */
	writel(0, ioaddr + MPC);
	/* no early-rx interrupts. Configure the device for not generating early interrupts.*/
	writew((readw(ioaddr + MULINT) & 0xF000), ioaddr + MULINT);
	/* Enable all known interrupts by setting the interrupt mask. */
	writel(INT_MASK,ioaddr + IMR);
	netif_start_queue (dev); // allow transmit
	return;
}

static int rtl8139_open(struct net_device *dev){
	int retval;
	struct rtl8139_priv *tc=netdev_priv(dev);	
	/* get the IRQ
    	* second arg is interrupt handler
    	* third is flags, 0 means no IRQ sharing  requesting function is either 0 to indicate success */
	//retval=request_irq(dev->irq,(irq_handler_t)rtl8139_interrupt,IRQF_SHARED,dev->name,dev);
	retval=request_irq(dev->irq,(irq_handler_t)rtl8139_interrupt,0,dev->name,dev);
	if(retval)
		return retval;
	/* get memory for Tx buffers
	 * memory must be DMAable  */
	/*
	 * To allocate and map large (PAGE_SIZE or so) consistent DMA regions,
	 * you should do: dma_addr_t dma_handle; cpu_addr = pci_alloc_consistent(dev, size, &dma_handle);*/
	tc->tx_bufs=pci_alloc_consistent(tc->pci_dev,TOTAL_TX_BUF_SIZE,&tc->tx_bufs_dma);
	tc->rx_ring=pci_alloc_consistent(tc->pci_dev,RX_BUF_TOT_LEN,&tc->rx_ring_dma);
	if((!tc->tx_bufs) || (!tc->rx_ring)){
		free_irq(dev->irq, dev);
		if(tc->tx_bufs){
			pci_free_consistent(tc->pci_dev,TOTAL_TX_BUF_SIZE,tc->tx_bufs,tc->tx_bufs_dma);
			tc->tx_bufs = NULL;
		}
		if(tc->rx_ring){
			 pci_free_consistent(tc->pci_dev,RX_BUF_TOT_LEN,tc->rx_ring,tc->rx_ring_dma);
			 tc->rx_ring = NULL;
		}
		return -ENOMEM;
	}
	tc->tx_flag=0;
	rtl8139_init_ring(dev);
	rtl8139_hw_start(dev);
	return 0;
}

static int rtl8139_stop(struct net_device *dev){
	struct rtl8139_priv *priv=netdev_priv(dev);
	struct pci_dev *pdev= priv->pci_dev;
	free_irq(pdev->irq, dev);
	pci_free_consistent(priv->pci_dev,TOTAL_TX_BUF_SIZE,priv->tx_bufs,priv->tx_bufs_dma);
	pci_free_consistent(priv->pci_dev,RX_BUF_TOT_LEN,priv->rx_ring,priv->rx_ring_dma);
	priv->cur_tx = 0;
	priv->rx_ring = 0;
	pr_info("rtl8139 Device Stoped\n");
	return 0;
}

static int rtl8139_start_xmit(struct sk_buff *skb,struct net_device *dev){
	struct rtl8139_priv *priv=netdev_priv(dev);
	void __iomem *ioaddr = priv->mmio_addr;
	unsigned int entry = priv->cur_tx;
	unsigned int len = skb->len;
	if (len < TX_BUF_SIZE) {
		if(len<ETH_MIN_LEN) memset(priv->tx_buf[entry],0,ETH_MIN_LEN);
		skb_copy_and_csum_dev(skb,priv->tx_buf[entry]); // which copies the packet contents to the DMA capable memory.
		dev_kfree_skb(skb);
	}
	else{
		dev_kfree_skb(skb);
		return 0;
	}
	writel(priv->tx_flag|max(len, (unsigned int)ETH_MIN_LEN),ioaddr + TSD0 + (entry *sizeof (u32)));
	entry++;
	priv->cur_tx = entry % NUM_TX_DESC;
	if (priv->cur_tx == priv->dirty_tx){
		netif_stop_queue(dev);
	}
	return 0;
}

static struct net_device_stats* rtl8139_get_stats(struct net_device *dev){
	struct rtl8139_priv *priv=netdev_priv(dev);
	void __iomem *ioaddr = priv->mmio_addr;
	if(netif_running(dev)){
		priv->stats.rx_missed_errors += readl(ioaddr+MPC);
		writel(0,ioaddr+MPC); 
	}
	return  &(priv->stats);
}
struct net_device_ops rtl8139_device_ops={
	.ndo_open       = rtl8139_open,
	.ndo_stop       = rtl8139_stop,
	.ndo_start_xmit = rtl8139_start_xmit,
	.ndo_get_stats  = rtl8139_get_stats,
};

int __init rtl8139_init_module(void){
	struct pci_dev *pdev;
	unsigned long mmio_start, mmio_end, mmio_len, mmio_flags;
	void __iomem *ioaddr;
	struct rtl8139_priv *priv;
	int i;
	printk("%s: Initialization of REALTEK Network Device driver\n",__func__);
	pdev=rtl8139_probe();
	if(!pdev)
		return 0;
	if(rtl8139_init(pdev,&rtl8139_dev)){
		pr_err("Couldn't initialize device\n");
		return 0;
	}
	priv=netdev_priv(rtl8139_dev);   /* rtl8139 private information */
	/* get PCI memory mapped I/O space base address from BAR1 */
	mmio_start=pci_resource_start(pdev, 1); /*The function returns the first address (memory address or I/O port number) associated with one of the six PCI I/O regions*/
	/*The function returns the last address that is part of the I/O region number bar. Note that this is the last usable address, not the first address after the region.*/
	mmio_end=pci_resource_end(pdev, 1);
	mmio_len=pci_resource_len(pdev,1);
	mmio_flags=pci_resource_flags(pdev, 1); /*This function returns the flags associated with this resource.*/
	/*it is memory( or anything that can be mapped as memory :-)) then it's IORESOURCE_MEM #define IORESOURCE_MEM	0x00000200 in ioport.h*/
	if(!(mmio_flags & IORESOURCE_MEM)){
		pr_err("Region is not MMI/O region\n");
		goto cleanup1;
	}
	/* get PCI memory space */
	if(pci_request_regions(pdev,DRIVER)){/*Returns 0 on success, or EBUSY on error. A warning message is also printed on failure.*/
		pr_err("Couldn't get PCI region");
		goto cleanup1;
	}
	   /* Enable bus mastering of the PCI device to enable the device to initiate transactions  */
	pci_set_master(pdev); /*pci_set_master() will enable DMA by setting the bus master bit in the PCI_COMMAND register*/
	 /* ioremap MMI/O region */
	/*it must first set up an appropriate kernel page-table mapping  I/O memory may or may not be accessed through page tables */
	/*When access passes though page tables, the kernel must first arrange for the physical address to be visible from your driver, 
	 * and this usually means that you must call ioremap before doing any I/O. #include <asm/io.h>*/
	ioaddr=ioremap(mmio_start, mmio_len);
	if(!ioaddr){
		pr_err("Couldn't ioremap\n");
		goto cleanup2;
	}
	rtl8139_dev->base_addr=(long)ioaddr;
	priv->mmio_addr=ioaddr;
	priv->regs_len=mmio_len;
	/* UPDATE NET_DEVICE */
	for(i=0;i<6;i++){ /* Hardware Address */
		rtl8139_dev->dev_addr[i]=readb((const volatile void *)rtl8139_dev->base_addr + i);
		rtl8139_dev->broadcast[i]=0xff;
	}
	/*The "hardware header length" is the number of octets that lead the transmitted packet before IP header, or other protocol information. The value of hard_header_len is 14 for Et	  hernet interfaces. */
	rtl8139_dev->hard_header_len = 14; 
	memcpy(rtl8139_dev->name, DRIVER, sizeof(DRIVER)); /* Device Name */
	rtl8139_dev->irq = pdev->irq;  /* Interrupt Number */
	rtl8139_dev->netdev_ops=&rtl8139_device_ops;
	 /* register the device */
	if(register_netdev(rtl8139_dev)){
		pr_err("Couldn't register netdevice\n");
		goto cleanup0;
	}
	return 0;
cleanup0:
	iounmap(priv->mmio_addr);

cleanup2:
	pci_release_regions(priv->pci_dev);

cleanup1: 
	 free_netdev(rtl8139_dev);
	 return 0;
}

void __exit rtl8139_cleanup_module(void){
	struct rtl8139_priv *priv;
	priv=netdev_priv(rtl8139_dev);   /* rtl8139 private information */
	iounmap(priv->mmio_addr);
	pci_release_regions(priv->pci_dev);
	unregister_netdev(rtl8139_dev);
	pci_disable_device(priv->pci_dev);
	printk("%s: Cleanup module is executed well\n",__func__);
}



MODULE_LICENSE("GPL");
MODULE_AUTHOR("beingchandanjha@gmail.com");
MODULE_DESCRIPTION("Basic Network driver");
MODULE_VERSION(".1");

module_init(rtl8139_init_module);
module_exit(rtl8139_cleanup_module);


/*https://github.com/profglavcho/mt6577-kernel-3.10.65/blob/master/Documentation/PCI/pci.txt*/

