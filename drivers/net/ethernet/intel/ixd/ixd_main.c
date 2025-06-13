// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2025 Intel Corporation */

#include "ixd.h"
#include "ixd_lan_regs.h"

MODULE_DESCRIPTION("Intel(R) Control Plane Function Device Driver");
MODULE_IMPORT_NS("LIBIE_CP");
MODULE_IMPORT_NS("LIBIE_PCI");
MODULE_LICENSE("GPL");

/**
 * ixd_remove - remove a CPF PCI device
 * @pdev: PCI device being removed
 */
static void ixd_remove(struct pci_dev *pdev)
{
	struct ixd_adapter *adapter = pci_get_drvdata(pdev);

	/* Do not mix removal with (re)initialization */
	cancel_delayed_work_sync(&adapter->init_task.init_work);
	/* Leave the device clean on exit */
	ixd_trigger_reset(adapter);
	ixd_deinit_dflt_mbx(adapter);

	libie_pci_unmap_all_mmio_regions(&adapter->cp_ctx.mmio_info);
	libie_pci_deinit_dev(pdev);
}

/**
 * ixd_shutdown - shut down a CPF PCI device
 * @pdev: PCI device being shut down
 */
static void ixd_shutdown(struct pci_dev *pdev)
{
	ixd_remove(pdev);

	if (system_state == SYSTEM_POWER_OFF)
		pci_set_power_state(pdev, PCI_D3hot);
}

/**
 * ixd_iomap_regions - iomap PCI BARs
 * @adapter: adapter to map memory regions for
 *
 * Returns: %0 on success, negative on failure
 */
static int ixd_iomap_regions(struct ixd_adapter *adapter)
{
	const struct ixd_bar_region regions[] = {
		{
			.offset = PFGEN_RTRIG,
			.size = PFGEN_RTRIG_REG_LEN,
		},
		{
			.offset = PF_FW_MBX,
			.size = PF_FW_MBX_REG_LEN,
		},
	};

	for (int i = 0; i < ARRAY_SIZE(regions); i++) {
		struct libie_mmio_info *mmio_info = &adapter->cp_ctx.mmio_info;
		bool map_ok;

		map_ok = libie_pci_map_mmio_region(mmio_info,
						   regions[i].offset,
						   regions[i].size);
		if (!map_ok) {
			dev_err(ixd_to_dev(adapter),
				"Failed to map PCI device MMIO region\n");

			libie_pci_unmap_all_mmio_regions(mmio_info);
			return -EIO;
		}
	}

	return 0;
}

/**
 * ixd_probe - probe a CPF PCI device
 * @pdev: corresponding PCI device
 * @ent: entry in ixd_pci_tbl
 *
 * Returns: %0 on success, negative errno code on failure
 */
static int ixd_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct ixd_adapter *adapter;
	int err;

	if (WARN_ON(ent->device != IXD_DEV_ID_CPF))
		return -EINVAL;

	adapter = devm_kzalloc(&pdev->dev, sizeof(*adapter), GFP_KERNEL);
	if (!adapter)
		return -ENOMEM;

	adapter->cp_ctx.mmio_info.pdev = pdev;
	INIT_LIST_HEAD(&adapter->cp_ctx.mmio_info.mmio_list);

	err = libie_pci_init_dev(pdev);
	if (err)
		return err;

	pci_set_drvdata(pdev, adapter);

	err = ixd_iomap_regions(adapter);
	if (err)
		goto deinit_dev;

	INIT_DELAYED_WORK(&adapter->init_task.init_work,
			  ixd_init_task);

	ixd_trigger_reset(adapter);
	queue_delayed_work(system_unbound_wq, &adapter->init_task.init_work,
			   msecs_to_jiffies(500));

	return 0;

deinit_dev:
	libie_pci_deinit_dev(pdev);

	return err;
}

static const struct pci_device_id ixd_pci_tbl[] = {
	{ PCI_VDEVICE(INTEL, IXD_DEV_ID_CPF) },
	{ }
};
MODULE_DEVICE_TABLE(pci, ixd_pci_tbl);

static struct pci_driver ixd_driver = {
	.name			= KBUILD_MODNAME,
	.id_table		= ixd_pci_tbl,
	.probe			= ixd_probe,
	.remove			= ixd_remove,
	.shutdown		= ixd_shutdown,
};
module_pci_driver(ixd_driver);
