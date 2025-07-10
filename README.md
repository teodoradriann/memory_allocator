# 🧠 OS Memory Allocator
> **Author:** Miron Teodor Adrian  

---

## 📋 Overview

**OS Memory Allocator** is a custom implementation of dynamic memory allocation functions (`malloc`, `calloc`, `realloc`, `free`) that provides an efficient alternative to the standard library implementations. The allocator uses a combination of `sbrk()` and `mmap()` system calls to manage memory efficiently based on allocation size and usage patterns.

## 🎯 Key Features

- ✅ **Hybrid Allocation Strategy** - Uses `sbrk()` for small allocations and `mmap()` for large ones
- ✅ **Memory Coalescing** - Automatically merges adjacent free blocks
- ✅ **Block Splitting** - Splits large blocks when smaller allocations are needed
- ✅ **Best-Fit Algorithm** - Finds the smallest suitable block to minimize fragmentation
- ✅ **Memory Alignment** - Ensures 8-byte alignment for optimal performance
- ✅ **Overflow Protection** - Prevents integer overflow in `calloc`
- ✅ **Zero Initialization** - `calloc` properly initializes memory to zero

---

## 🏗️ Architecture

### Memory Management Strategy

| Allocation Size | Method | Threshold |
|-----------------|--------|-----------|
| **Small** (< 128KB) | `sbrk()` | Heap expansion |
| **Large** (≥ 128KB) | `mmap()` | Direct mapping |

### Block Structure

```c
struct block_meta {
    size_t size;           // Size of the allocated block
    int status;            // STATUS_ALLOC, STATUS_FREE, STATUS_MAPPED
    struct block_meta *next;  // Next block in the linked list
    struct block_meta *prev;  // Previous block in the linked list
};
```

### Key Constants

```c
#define MMAP_THRESHOLD (128 * KB)  // 128 KB threshold
#define PREALLOC_SIZE (128 * KB)   // Initial heap preallocation
#define ALIGNMENT_SIZE 8           // 8-byte alignment
```

---

## 🔧 Core Functions

### `os_malloc(size_t size)`
- **Purpose:** Allocate memory block of specified size
- **Strategy:** 
  - Uses best-fit algorithm to find suitable free blocks
  - Splits blocks when they're larger than needed
  - Expands heap or uses mmap based on size threshold

### `os_free(void *ptr)`
- **Purpose:** Deallocate memory block
- **Strategy:**
  - Marks `sbrk()`-allocated blocks as free (enables coalescing)
  - Immediately unmaps `mmap()`-allocated blocks

### `os_calloc(size_t nmemb, size_t size)`
- **Purpose:** Allocate and zero-initialize array
- **Features:**
  - Overflow protection for multiplication
  - Uses page size as threshold instead of MMAP_THRESHOLD
  - Initializes allocated memory to zero

### `os_realloc(void *ptr, size_t size)`
- **Purpose:** Resize existing memory block
- **Strategy:**
  - Attempts in-place expansion when possible
  - Falls back to new allocation + copy when necessary
  - Handles both heap and mmap-allocated blocks

---

## 🚀 Advanced Features

### Memory Coalescing
```c
void coalesce(void)
```
- **Function:** Merges adjacent free blocks to reduce fragmentation
- **Trigger:** Called before each allocation attempt
- **Benefits:** Reduces external fragmentation and improves memory utilization

### Block Splitting
```c
void split(struct block_meta *block, size_t size)
```
- **Function:** Divides large blocks into smaller ones
- **Condition:** Only splits if remainder can hold another block + metadata
- **Benefits:** Minimizes internal fragmentation

### Smart Expansion
```c
struct block_meta *expand(struct block_meta *block, size_t size, int where)
```
- **Function:** Attempts to expand existing blocks in-place
- **Strategy:** 
  - Merges with adjacent free blocks
  - Extends heap for last non-mapped block
- **Benefits:** Avoids costly memory copies in `realloc`

---

## 📊 Performance Characteristics

### Allocation Strategy Benefits

| Feature | Benefit |
|---------|---------|
| **Hybrid sbrk/mmap** | Optimal performance for different allocation sizes |
| **Best-fit algorithm** | Reduces memory fragmentation |
| **Block coalescing** | Prevents heap fragmentation over time |
| **In-place expansion** | Reduces realloc overhead |
| **8-byte alignment** | Ensures optimal CPU access patterns |

### Memory Layout

```
Heap (sbrk):  [Block1][Block2][Block3]...
Mapped:       [Large Block] (separate mmap regions)
```

---

## 🔬 Implementation Details

### Alignment Strategy
- **8-byte alignment** ensures compatibility with most CPU architectures
- **ALIGN macro** rounds up sizes to nearest multiple of 8
- **Consistent alignment** across all allocation functions

### Threshold Management
- **128KB threshold** balances between heap and mmap usage
- **Page size threshold** for calloc provides better performance for arrays
- **Dynamic threshold** consideration based on allocation patterns

### Error Handling
- **Robust error checking** for system call failures
- **Overflow protection** in multiplication operations
- **Null pointer handling** in all functions

---

## 🔍 Key Advantages

- **Memory Efficiency:** Intelligent block management reduces waste
- **Performance:** Optimized for both small and large allocations
- **Compatibility:** Drop-in replacement for standard library functions
- **Robustness:** Comprehensive error handling and edge case management
- **Scalability:** Efficient handling of varying allocation patterns

---

*Built with modern memory management principles and optimized for real-world usage patterns.*
