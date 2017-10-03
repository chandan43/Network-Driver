#include <linux/module.h>
#include <linux/init.h>
#include <linux/pci.h>

#define REALTEK_VENDER_ID  0x10EC
#define REALTEK_DEVICE_ID   0x8139

int __init rtl8139_init(void){
	struct pci_dev *pdev;
	printk("%s: Initialization of Network Device driver\n",__func__);
	/*begin or continue searching for a PCI device by vendor/device id. struct pci_dev *pci_get_device(unsigned int vendor, unsigned int device,struct pci_dev *from);*/
	pdev=pci_get_device(REALTEK_VENDER_ID,REALTEK_DEVICE_ID,NULL);
	if(!pdev)
		pr_err("rtl8139: Device not found\n");
	else
		pr_info("rtl8139: Device found\n");
	return 0;
}

void __exit rtl8139_exit(void){
	printk("%s: Good Bye.!\n",__func__);
}



MODULE_LICENSE("GPL");
MODULE_AUTHOR("beingchandanjha@gmail.com");
MODULE_DESCRIPTION("Basic Network driver");

module_init(rtl8139_init);
module_exit(rtl8139_exit);



