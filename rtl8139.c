#include <linux/module.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/netdevice.h> 
#include <linux/etherdevice.h>
#include <linux/kernel.h>
#include <linux/io.h>

#define REALTEK_VENDER_ID  0x10EC
#define REALTEK_DEVICE_ID   0x8139
#define DRIVER "rtl8139"
static struct net_device *rtl8139_dev;

struct rtl8139_priv {
	struct pci_dev *pci_dev; /*PCI device */
	void *mmio_addr;  /*memory mapped I/O addr */
	unsigned long regs_len; /* length of I/O or MMI/O region */
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

static int rtl8139_open(struct net_device *dev){
	pr_info("rtl8139 Device opened\n");
	return 0;
}

static int rtl8139_stop(struct net_device *dev){
	pr_info("rtl8139 Device Stoped\n");
	return 0;
}

static int rtl8139_start_xmit(struct sk_buff *skb,struct net_device *dev){
	pr_info("rtl8139_start_xmit is called\n");
	return 0;
}

static struct net_device_stats* rtl8139_get_stats(struct net_device *dev){
	pr_info("rtl8139_get_stats is called\n");
	return 0;
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
	void *ioaddr;
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

