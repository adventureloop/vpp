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
#include <sys/ioctl.h>
#include <sys/eventfd.h>

#include <sys/pciio.h>

#include <fcntl.h>
#include <dirent.h>
#include <net/if.h>

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

#define NOTIMPL printf("%s:%d: Not implemented\n", __func__, __LINE__); __builtin_debugtrap();

uword
vlib_pci_get_private_data (vlib_main_t * vm, vlib_pci_dev_handle_t h)
{
	NOTIMPL
	return 0;
}

void
vlib_pci_set_private_data (vlib_main_t * vm, vlib_pci_dev_handle_t h,
			   uword private_data)
{
	NOTIMPL
}

vlib_pci_addr_t *
vlib_pci_get_addr (vlib_main_t * vm, vlib_pci_dev_handle_t h)
{
	NOTIMPL
	return NULL;
}

u32
vlib_pci_get_numa_node (vlib_main_t * vm, vlib_pci_dev_handle_t h)
{
	NOTIMPL
	return 0;
}

u32
vlib_pci_get_num_msix_interrupts (vlib_main_t * vm, vlib_pci_dev_handle_t h)
{
	NOTIMPL
  return 0;
}

/* Call to allocate/initialize the pci subsystem.
   This is not an init function so that users can explicitly enable
   pci only when it's needed. */
clib_error_t *pci_bus_init (vlib_main_t * vm);

//freebsd_pci_main_t freebsd_pci_main;

vlib_pci_device_info_t *
vlib_pci_get_device_info (vlib_main_t * vm, vlib_pci_addr_t * addr,
			  clib_error_t ** error)
{
/* Populate a vlib_pci_device_info_t from the given address */

  clib_error_t *err = NULL;
  vlib_pci_device_info_t *di = NULL;

  int fd = -1;
  struct pci_conf_io pci;
  struct pci_conf match;
  struct pci_match_conf pattern;
  bzero (&match, sizeof(match));
  bzero (&pattern, sizeof(pattern));

  pattern.pc_sel.pc_domain = addr->domain;
  pattern.pc_sel.pc_bus = addr->bus;
  pattern.pc_sel.pc_dev = addr->slot;
  pattern.pc_sel.pc_func = addr->function;
  pattern.flags = PCI_GETCONF_MATCH_DOMAIN | PCI_GETCONF_MATCH_BUS
    | PCI_GETCONF_MATCH_DEV | PCI_GETCONF_MATCH_FUNC;
                                      
  pci.pat_buf_len = sizeof (pattern);
  pci.num_patterns = 1;
  pci.patterns = &pattern;
  pci.match_buf_len = sizeof (match);
  pci.num_matches = 1;
  pci.matches = &match;
  pci.offset = 0;
  pci.generation = 0;
  pci.status = 0;
                                      
  fd = open ("/dev/pci", 0);             
  if (fd == -1) {                       
    err = clib_error_return_unix (0, "open '/dev/pci'");
    goto error;
  }                                     
                                        
  if (ioctl (fd, PCIOCGETCONF, &pci) == -1) {
    err = clib_error_return_unix (0, "reading PCIOCGETCONF");
    goto error;
  }                                     

  if (pci.num_matches != 1) {
    __builtin_debugtrap();
    goto error;
  }

  di = clib_mem_alloc (sizeof (vlib_pci_device_info_t));
  clib_memset (di, 0, sizeof (vlib_pci_device_info_t));

  di->addr.as_u32 = addr->as_u32;
  di->numa_node = 0;  /* TODO: Place holder until we have NUMA on FreeBSD */

  di->device_class = match.pc_class;
  di->vendor_id = match.pc_vendor;
  di->device_id = match.pc_device;
  di->revision = match.pc_revid;

  di->product_name = NULL; //(u8 *) "NOTSUPPORTED";
  di->vpd_r = 0;
  di->vpd_w = 0;

// This might be working or the source of a problem
  di->driver_name = format(0, "%s", &match.pd_name);
//di->driver_name = format (0, "<NONE>%c", 0);	// Fall back to not caring

  di->iommu_group = -1;

  goto done;

error:
  vlib_pci_free_device_info (di);
  di = NULL;
done:
  if (error)
    *error = err;
  close (fd);
  return di;
}

clib_error_t *__attribute__ ((weak))
vlib_pci_get_device_root_bus (vlib_pci_addr_t *addr, vlib_pci_addr_t *root_bus)
{
	NOTIMPL
  return NULL;
}

clib_error_t *
vlib_pci_bind_to_uio (vlib_main_t *vm, vlib_pci_addr_t *addr,
		      char *uio_drv_name, int force)
{
  clib_error_t *error = 0;

  if (error) {
    return error;
  }

  if (strncmp("auto", uio_drv_name, 5) == 0) {

// TODO: Should confirm that nic_uio is loaded here and return an error
    uio_drv_name = "nic_uio";
  }

  return error;
}

clib_error_t *
vlib_pci_register_intx_handler (vlib_main_t * vm, vlib_pci_dev_handle_t h,
				pci_intx_handler_function_t * intx_handler)
{
	NOTIMPL
  return NULL;
}

clib_error_t *
vlib_pci_unregister_intx_handler (vlib_main_t *vm, vlib_pci_dev_handle_t h)
{
	NOTIMPL
  return NULL;
}

clib_error_t *
vlib_pci_register_msix_handler (vlib_main_t * vm, vlib_pci_dev_handle_t h,
				u32 start, u32 count,
				pci_msix_handler_function_t * msix_handler)
{
	NOTIMPL
  return NULL;
}

clib_error_t *
vlib_pci_unregister_msix_handler (vlib_main_t *vm, vlib_pci_dev_handle_t h,
				  u32 start, u32 count)
{
	NOTIMPL
	return NULL;
}

clib_error_t *
vlib_pci_enable_msix_irq (vlib_main_t * vm, vlib_pci_dev_handle_t h,
			  u16 start, u16 count)
{
	NOTIMPL
	return NULL;
}

uword
vlib_pci_get_msix_file_index (vlib_main_t * vm, vlib_pci_dev_handle_t h,
			      u16 index)
{
	NOTIMPL
	return 0;
}

clib_error_t *
vlib_pci_disable_msix_irq (vlib_main_t * vm, vlib_pci_dev_handle_t h,
			   u16 start, u16 count)
{
	NOTIMPL
	return NULL;
}


/* Configuration space read/write. */
clib_error_t *
vlib_pci_read_write_config (vlib_main_t * vm, vlib_pci_dev_handle_t h,
			    vlib_read_or_write_t read_or_write,
			    uword address, void *data, u32 n_bytes)
{
	NOTIMPL
	return NULL;
}

clib_error_t *
vlib_pci_map_region (vlib_main_t * vm, vlib_pci_dev_handle_t h, u32 resource,
		     void **result)
{
	NOTIMPL
  return NULL;
}

clib_error_t *
vlib_pci_map_region_fixed (vlib_main_t * vm, vlib_pci_dev_handle_t h,
			   u32 resource, u8 * addr, void **result)
{
	NOTIMPL
  return NULL;
}

clib_error_t *
vlib_pci_io_region (vlib_main_t * vm, vlib_pci_dev_handle_t h, u32 resource)
{
	NOTIMPL
  return NULL;
}

clib_error_t *
vlib_pci_read_write_io (vlib_main_t * vm, vlib_pci_dev_handle_t h,
			vlib_read_or_write_t read_or_write,
			uword offset, void *data, u32 length)
{
	NOTIMPL
  return NULL;
}

clib_error_t *
vlib_pci_map_dma (vlib_main_t * vm, vlib_pci_dev_handle_t h, void *ptr)
{
	NOTIMPL
  return NULL;
}

int
vlib_pci_supports_virtual_addr_dma (vlib_main_t * vm, vlib_pci_dev_handle_t h)
{
	NOTIMPL
  return 0;
}

clib_error_t *
vlib_pci_device_open (vlib_main_t * vm, vlib_pci_addr_t * addr,
		      pci_device_id_t ids[], vlib_pci_dev_handle_t * handle)
{
	NOTIMPL
  return NULL;
}

void
vlib_pci_device_close (vlib_main_t * vm, vlib_pci_dev_handle_t h) { }

void
init_device_from_registered (vlib_main_t * vm, vlib_pci_device_info_t * di) { }

static int
pci_addr_cmp (void *v1, void *v2)
{
  vlib_pci_addr_t *a1 = v1;
  vlib_pci_addr_t *a2 = v2;

  if (a1->domain > a2->domain)
    return 1;
  if (a1->domain < a2->domain)
    return -1;
  if (a1->bus > a2->bus)
    return 1;
  if (a1->bus < a2->bus)
    return -1;
  if (a1->slot > a2->slot)
    return 1;
  if (a1->slot < a2->slot)
    return -1;
  if (a1->function > a2->function)
    return 1;
  if (a1->function < a2->function)
    return -1;
  return 0;
}

vlib_pci_addr_t *
vlib_pci_get_all_dev_addrs ()
{
  vlib_pci_addr_t *addrs = 0;

  int fd = -1;
  struct pci_conf_io pci;               
  struct pci_conf matches[32];          
  bzero(matches, sizeof(matches));      
                                      
  pci.pat_buf_len = 0;
  pci.num_patterns = 0;
  pci.patterns = NULL;
  pci.match_buf_len = sizeof(matches);
  pci.num_matches = 32;
  pci.matches = (struct pci_conf *)&matches;
  pci.offset = 0;
  pci.generation = 0;
  pci.status = 0;
                                      
  fd = open ("/dev/pci", 0);             
  if (fd == -1) {                       
    perror ("opening /dev/pci");   
    return (NULL);
  }                                     
                                        
  if (ioctl (fd, PCIOCGETCONF, &pci) == -1) {
    perror ("reading pci config"); 
    close(fd);
    return (NULL);
  }                                     

  for (int i = 0; i < pci.num_matches; i++) {    
    struct pci_conf *m = &pci.matches[i];
    vlib_pci_addr_t addr;
#if 0
    printf("%d: class=%x subclass=%x rev=%x hdr=%x vendor=%x device=%x subvendor=%x subdevice=%x\n",
            i, m->pc_class, m->pc_subclass, m->pc_revid, m->pc_hdr, m->pc_vendor,
	            m->pc_device, m->pc_subvendor, m->pc_subdevice);
#endif

    addr.domain = m->pc_sel.pc_domain;
    addr.bus = m->pc_sel.pc_bus;
    addr.slot = m->pc_sel.pc_dev;      // TODO: bit magic required?
    addr.function = m->pc_sel.pc_func;  // TODO: bit magic required?

    vec_add1 (addrs, addr);
  }

  vec_sort_with_function (addrs, pci_addr_cmp);
  close (fd);

  return addrs;
}

clib_error_t *
freebsd_pci_init (vlib_main_t * vm)
{
  vlib_pci_main_t *pm = &pci_main;
  vlib_pci_addr_t *addr = 0, *addrs;

  pm->vlib_main = vm;

  ASSERT (sizeof (vlib_pci_addr_t) == sizeof (u32));

  addrs = vlib_pci_get_all_dev_addrs ();
  /* *INDENT-OFF* */
  vec_foreach (addr, addrs)
    {
      vlib_pci_device_info_t *d;
      if ((d = vlib_pci_get_device_info (vm, addr, 0)))
        {
          init_device_from_registered (vm, d);
          vlib_pci_free_device_info (d);
        }
    }
  /* *INDENT-ON* */
    
  return 0;
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
