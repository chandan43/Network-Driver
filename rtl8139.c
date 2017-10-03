#include <linux/module.h>
#include <linux/init.h>
#include <linux/pci.h>

#define REALTEK_VENDER_ID  0x10EC
#define REALTEK_DEVICE_ID   0x8139
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


int __init rtl8139_init(void){
	struct pci_dev *pdev;
	printk("%s: Initialization of REALTEK Network Device driver\n",__func__);
	pdev=rtl8139_probe();
	if(!pdev)
		return 0;
	return 0;
}

void __exit rtl8139_exit(void){
	printk("%s: Good Bye.!\n",__func__);
}



MODULE_LICENSE("GPL");
MODULE_AUTHOR("beingchandanjha@gmail.com");
MODULE_DESCRIPTION("Basic Network driver");
MODULE_VERSION(".1");

module_init(rtl8139_init);
module_exit(rtl8139_exit);


/*https://github.com/profglavcho/mt6577-kernel-3.10.65/blob/master/Documentation/PCI/pci.txt*/
