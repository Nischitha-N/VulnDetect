/**
 * VulnDetect C++ Semantic Analysis Corpus Fixture.
 * Demonstrates Move semantics, Mismatched new/delete, Iterator invalidation,
 * Polymorphic destruction, Dangling local references, and Safe RAII idioms.
 */

#include <iostream>
#include <vector>
#include <string>
#include <memory>

// ─── 1. Use After Move ───────────────────────────────────────────────────────

void test_use_after_move(void) {
    std::string s = "important_data";
    std::string s2 = std::move(s);
    std::cout << s << std::endl; // VULNERABLE: Use-after-move
}

// ─── 2. new[] / delete Mismatches ────────────────────────────────────────────

void test_array_delete_mismatch(void) {
    int *arr = new int[100];
    delete arr; // VULNERABLE: Array allocated with new[] deleted with scalar delete
}

void test_scalar_delete_mismatch(void) {
    int *scalar = new int(42);
    delete[] scalar; // VULNERABLE: Scalar allocated with new deleted with delete[]
}

// ─── 3. Returning Reference to Local Stack Object ────────────────────────────

int &test_dangling_local_return(void) {
    int local_val = 100;
    return local_val; // VULNERABLE: Dangling reference to local stack variable
}

// ─── 4. Dangling Pointer to Temporary Object ─────────────────────────────────

void test_dangling_temporary(void) {
    const char *p = std::string("temporary_string").c_str(); // VULNERABLE: Temporary string destroyed at semicolon
}

// ─── 5. Iterator Invalidation on Containers ──────────────────────────────────

void test_iterator_invalidation(void) {
    std::vector<int> v = {1, 2, 3};
    auto it = v.begin();
    v.push_back(4); // Reallocation may invalidate all iterators
    *it = 10;       // VULNERABLE: Dereferencing invalidated iterator
}

// ─── 6. Polymorphic Deletion without Virtual Destructor ──────────────────────

class Base {
public:
    virtual void do_work();
    ~Base(); // NON-VIRTUAL destructor!
};

class Derived : public Base {
public:
    void do_work() override;
    ~Derived();
};

void test_polymorphic_deletion(void) {
    Base *b = new Derived();
    delete b; // VULNERABLE: Undefined behavior deleting through base with non-virtual dtor
}

// ─── 7. Safe RAII Idioms (Safe) ──────────────────────────────────────────────

void test_safe_raii(void) {
    auto u = std::make_unique<int>(10);
    std::vector<int> safe_vec = {1, 2, 3};
    safe_vec.push_back(4);
    int val = safe_vec[0]; // SAFE: standard index access
}
