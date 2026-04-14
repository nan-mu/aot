// Extracted from /Users/nan/bs/aot/src/verifier.c
static void *realloc_array(void *arr, size_t old_n, size_t new_n, size_t size)
{
	size_t alloc_size;
	void *new_arr;

	if (!new_n || old_n == new_n)
		goto out;

	alloc_size = kmalloc_size_roundup(size_mul(new_n, size));
	new_arr = krealloc(arr, alloc_size, GFP_KERNEL_ACCOUNT);
	if (!new_arr) {
		kfree(arr);
		return NULL;
	}
	arr = new_arr;

	if (new_n > old_n)
		memset(arr + old_n * size, 0, (new_n - old_n) * size);

out:
	return arr ? arr : ZERO_SIZE_PTR;
}


