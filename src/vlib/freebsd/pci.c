/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * pci.c: Linux user space PCI bus management.
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <vlib/vlib.h>
#include <vlib/pci/pci.h>
#include <vlib/unix/unix.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/eventfd.h>

#if 0
#define SYSFS_DEVICES_PCI "/sys/devices/pci"
static const char *sysfs_pci_dev_path = "/sys/bus/pci/devices";
static const char *sysfs_pci_drv_path = "/sys/bus/pci/drivers";
static char *sysfs_mod_vfio_noiommu =
  "/sys/module/vfio/parameters/enable_unsafe_noiommu_mode";

VLIB_REGISTER_LOG_CLASS (pci_log, static) = {
  .class_name = "pci",
  .subclass_name = "linux",
};

#define log_debug(p, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, pci_log.class, "%U: " f,                    \
	    format_vlib_pci_log, p->handle, ##__VA_ARGS__)
#define log_err(p, f, ...)                                                    \
  vlib_log (VLIB_LOG_LEVEL_ERR, pci_log.class, "%U: " f, format_vlib_pci_log, \
	    p->handle, ##__VA_ARGS__)

typedef struct
{
  int fd;
  void *addr;
  size_t size;
} linux_pci_region_t;

typedef struct
{
  int fd;
  u32 clib_file_index;
  union
  {
    pci_intx_handler_function_t *intx_handler;
    pci_msix_handler_function_t *msix_handler;
  };
} linux_pci_irq_t;

typedef enum
{
  LINUX_PCI_DEVICE_TYPE_UNKNOWN,
  LINUX_PCI_DEVICE_TYPE_UIO,
  LINUX_PCI_DEVICE_TYPE_VFIO,
} linux_pci_device_type_t;

typedef struct
{
  linux_pci_device_type_t type;
  vlib_pci_dev_handle_t handle;
  vlib_pci_addr_t addr;
  u32 numa_node;

  /* Resource file descriptors. */
  linux_pci_region_t *regions;

  /* File descriptor for config space read/write. */
  int config_fd;
  u64 config_offset;

  /* Device File descriptor */
  int fd;

  /* read/write file descriptor for io bar */
  int io_fd;
  u64 io_offset;

  /* Minor device for uio device. */
  u32 uio_minor;

  /* Interrupt handlers */
  linux_pci_irq_t intx_irq;
  linux_pci_irq_t *msix_irqs;

  /* private data */
  uword private_data;

  u8 supports_va_dma;

} linux_pci_device_t;

/* Pool of PCI devices. */
typedef struct
{
  vlib_main_t *vlib_main;
  linux_pci_device_t *linux_pci_devices;

} linux_pci_main_t;
#endif

extern vlib_pci_main_t freebsd_pci_main;

uword
vlib_pci_get_private_data (vlib_main_t * vm, vlib_pci_dev_handle_t h)
{
	return 0;
}

void
vlib_pci_set_private_data (vlib_main_t * vm, vlib_pci_dev_handle_t h,
			   uword private_data)
{
}

vlib_pci_addr_t *
vlib_pci_get_addr (vlib_main_t * vm, vlib_pci_dev_handle_t h)
{
	return NULL;
}

u32
vlib_pci_get_numa_node (vlib_main_t * vm, vlib_pci_dev_handle_t h)
{
	return 0;
}

u32
vlib_pci_get_num_msix_interrupts (vlib_main_t * vm, vlib_pci_dev_handle_t h)
{
  return 0;
}

/* Call to allocate/initialize the pci subsystem.
   This is not an init function so that users can explicitly enable
   pci only when it's needed. */
clib_error_t *pci_bus_init (vlib_main_t * vm);

//linux_pci_main_t linux_pci_main;

vlib_pci_device_info_t *
vlib_pci_get_device_info (vlib_main_t * vm, vlib_pci_addr_t * addr,
			  clib_error_t ** error)
{
  return NULL;
}

clib_error_t *__attribute__ ((weak))
vlib_pci_get_device_root_bus (vlib_pci_addr_t *addr, vlib_pci_addr_t *root_bus)
{
  return NULL;
}

clib_error_t *
vlib_pci_bind_to_uio (vlib_main_t *vm, vlib_pci_addr_t *addr,
		      char *uio_drv_name, int force)
{
	return NULL;
}

clib_error_t *
vlib_pci_register_intx_handler (vlib_main_t * vm, vlib_pci_dev_handle_t h,
				pci_intx_handler_function_t * intx_handler)
{
  return NULL;
}

clib_error_t *
vlib_pci_unregister_intx_handler (vlib_main_t *vm, vlib_pci_dev_handle_t h)
{
  return NULL;
}

clib_error_t *
vlib_pci_register_msix_handler (vlib_main_t * vm, vlib_pci_dev_handle_t h,
				u32 start, u32 count,
				pci_msix_handler_function_t * msix_handler)
{
  return NULL;
}

clib_error_t *
vlib_pci_unregister_msix_handler (vlib_main_t *vm, vlib_pci_dev_handle_t h,
				  u32 start, u32 count)
{
	return NULL;
}

clib_error_t *
vlib_pci_enable_msix_irq (vlib_main_t * vm, vlib_pci_dev_handle_t h,
			  u16 start, u16 count)
{
	return NULL;
}

uword
vlib_pci_get_msix_file_index (vlib_main_t * vm, vlib_pci_dev_handle_t h,
			      u16 index)
{
	return 0;
}

clib_error_t *
vlib_pci_disable_msix_irq (vlib_main_t * vm, vlib_pci_dev_handle_t h,
			   u16 start, u16 count)
{
	return NULL;
}


/* Configuration space read/write. */
clib_error_t *
vlib_pci_read_write_config (vlib_main_t * vm, vlib_pci_dev_handle_t h,
			    vlib_read_or_write_t read_or_write,
			    uword address, void *data, u32 n_bytes)
{
	return NULL;
}

clib_error_t *
vlib_pci_map_region (vlib_main_t * vm, vlib_pci_dev_handle_t h, u32 resource,
		     void **result)
{
  return NULL;
}

clib_error_t *
vlib_pci_map_region_fixed (vlib_main_t * vm, vlib_pci_dev_handle_t h,
			   u32 resource, u8 * addr, void **result)
{
  return NULL;
}

clib_error_t *
vlib_pci_io_region (vlib_main_t * vm, vlib_pci_dev_handle_t h, u32 resource)
{
  return NULL;
}

clib_error_t *
vlib_pci_read_write_io (vlib_main_t * vm, vlib_pci_dev_handle_t h,
			vlib_read_or_write_t read_or_write,
			uword offset, void *data, u32 length)
{
  return NULL;
}

clib_error_t *
vlib_pci_map_dma (vlib_main_t * vm, vlib_pci_dev_handle_t h, void *ptr)
{
  return NULL;
}

int
vlib_pci_supports_virtual_addr_dma (vlib_main_t * vm, vlib_pci_dev_handle_t h)
{
  return 0;
}

clib_error_t *
vlib_pci_device_open (vlib_main_t * vm, vlib_pci_addr_t * addr,
		      pci_device_id_t ids[], vlib_pci_dev_handle_t * handle)
{
  return NULL;
}

void
vlib_pci_device_close (vlib_main_t * vm, vlib_pci_dev_handle_t h) { }

void
init_device_from_registered (vlib_main_t * vm, vlib_pci_device_info_t * di) { }

vlib_pci_addr_t *
vlib_pci_get_all_dev_addrs ()
{
	return NULL;
}

clib_error_t *
freebsd_pci_init (vlib_main_t * vm)
{
  return NULL;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (freebsd_pci_init) =
{
  .runs_after = VLIB_INITS("unix_input_init"),
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
