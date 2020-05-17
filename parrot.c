#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/uaccess.h>

#include <xen/interface/xmp.h>

#define DEVICE_NAME "parrot"
#define CLASS_NAME "parrot"

#define parrot_info(msg, ...) printk(KERN_INFO msg, ##__VA_ARGS__)

struct parrot_message {
	char message[256];
	size_t message_size;
};

/*
 * Device relevant information
 */
static int major;
static int num_opens = 0;
static struct class* parrot_class = NULL;
static struct device* parrot_device = NULL;

/*
 * Parrot relevant information
 */
static uint16_t parrot_pdomain = 0;
static struct parrot_message *message = NULL;

static int parrot_open(struct inode *, struct file *);
static int parrot_release(struct inode *, struct file *);
static ssize_t parrot_read(struct file *, char *, size_t, loff_t *);
static ssize_t parrot_write(struct file *, const char *, size_t, loff_t *);

static struct file_operations fops =
{
	.open = parrot_open,
	.read = parrot_read,
	.write = parrot_write,
	.release = parrot_release,
};

static int parrot_open(struct inode *inodep, struct file *filep)
{
	num_opens++;
	parrot_info("parrot: Device has been opened %d time(s)\n", num_opens);

	return 0;
}

static ssize_t parrot_read(struct file *filep, char *buffer, size_t len,
	loff_t *offset)
{
	struct parrot_message *parrot_message;
	int error_count = 0;

	/*
	 * We are returning the last written message. Since the pointer has been
	 * signed upon allocating the object we need to authenticate it first.
	 */
	parrot_message = xmp_auth_ptr(message, THIS_MODULE, parrot_pdomain);

	parrot_info("parrot: %s", parrot_message->message);

	error_count = copy_to_user(buffer, parrot_message->message, len);
	if (error_count == 0)
		return 0;
	else {
		parrot_info("parrot: Failed to send %d characters to the user\n",
			error_count);

		return -EFAULT;
	}
}

static ssize_t parrot_write(struct file *filep, const char *buffer, size_t len,
	loff_t *offset)
{
	struct parrot_message *parrot_message;
	int error_count = 0;

	/*
	 * If there is already an isolated page present, we are going to free it.
	 * For that we have to authenticate the pointer in order to make sure that
	 * the pointer has not been meddled with and to get the unsigned pointer.
	 */
	if (message) {
		unsigned long addr = (unsigned long)xmp_auth_ptr(message, THIS_MODULE, parrot_pdomain);
		free_pages(addr, 0);
	}

	/*
	 * Allocate an isolated page for our example. The pdomain has to be
	 * encoded in the GFP flags.
	 */
	parrot_message = (void *)get_zeroed_page(XMP_GFP_FLAGS(parrot_pdomain, GFP_KERNEL));
	if (IS_ERR(parrot_message)) {
		parrot_info("Error in allocating free page for parrot message");
		return PTR_ERR(parrot_message);
	}

	/*
	 * In the current implementation, the allocated page always has RWX access
	 * permissions for the ap2m view in which we isolated the page in and only
	 * RO access for all other ap2m views.
	 *
	 * To write something to the isolated page, we need to switch to the
	 * allocated pdomain so that we can write access it.
	 */
	xmp_unprotect(parrot_pdomain);
	error_count = copy_from_user(parrot_message->message, buffer, len);
	parrot_message->message_size = len;
	xmp_protect();

	if (error_count != 0) {
		parrot_info("parrot: Error %d in copying message from user", error_count);
		return -EFAULT;
	}

	/*
	 * The allocated isolated page needs to be signed with the secret key
	 * of the allocated pdomain. This example will use THIS_MODULE as the
	 * context value for signing the pointer.
	 */
	message = xmp_sign_ptr(parrot_message, THIS_MODULE, parrot_pdomain);

	return len;
}

static int parrot_release(struct inode *inodep, struct file *filep)
{
	parrot_info("parrot: Device successfully closed\n");

	return 0;
}

static int __init parrot_init(void)
{
	parrot_info("parrot: Initializing parrot LKM\n");

	/*
	 * Allocate a new pdomain for this example.
	 */
	parrot_pdomain = xmp_alloc_pdomain();
	if (parrot_pdomain == XMP_MAX_PDOMAINS)
		return -EFAULT;

	major = register_chrdev(0, DEVICE_NAME, &fops);
	if (major < 0) {
		parrot_info( "parrot failed to register a major number\n");

		return major;
	}

	parrot_class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(parrot_class)) {
		unregister_chrdev(major, DEVICE_NAME);
		parrot_info( "Failed to register device class\n");

		return PTR_ERR(parrot_class);
	}

	parrot_device = device_create(parrot_class, NULL, MKDEV(major, 0),
		NULL, DEVICE_NAME);
	if (IS_ERR(parrot_device)){
		class_destroy(parrot_class);
		unregister_chrdev(major, DEVICE_NAME);
		parrot_info( "Failed to create the device\n");

		return PTR_ERR(parrot_device);
	}

	parrot_info("parrot: Successfully created parrot char device\n");

	return 0;
}

static void __exit parrot_exit(void)
{
	unsigned long addr;

	/*
	 * Free the allocated buffer.
	 */
	addr = (unsigned long)xmp_auth_ptr(message, THIS_MODULE, parrot_pdomain);
	free_pages(addr, 0);

	/*
	 * Free the allocated pdomain.
	 */
	xmp_free_pdomain(parrot_pdomain);

	device_destroy(parrot_class, MKDEV(major, 0));
	class_unregister(parrot_class);
	class_destroy(parrot_class);
	unregister_chrdev(major, DEVICE_NAME);

	parrot_info("parrot: Goodbye from the LKM!\n");
}

module_init(parrot_init);
module_exit(parrot_exit);

MODULE_LICENSE("GPL");
