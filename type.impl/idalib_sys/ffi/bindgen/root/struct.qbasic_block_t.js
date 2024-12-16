(function() {
    var type_impls = Object.fromEntries([["idalib_sys",[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-AsRef%3Crange_t%3E-for-qbasic_block_t\" class=\"impl\"><a href=\"#impl-AsRef%3Crange_t%3E-for-qbasic_block_t\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.83.0/core/convert/trait.AsRef.html\" title=\"trait core::convert::AsRef\">AsRef</a>&lt;<a class=\"struct\" href=\"idalib_sys/ffi/bindgen/root/struct.range_t.html\" title=\"struct idalib_sys::ffi::bindgen::root::range_t\">range_t</a>&gt; for <a class=\"struct\" href=\"idalib_sys/ffi/bindgen/root/struct.qbasic_block_t.html\" title=\"struct idalib_sys::ffi::bindgen::root::qbasic_block_t\">qbasic_block_t</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.as_ref\" class=\"method trait-impl\"><a href=\"#method.as_ref\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.83.0/core/convert/trait.AsRef.html#tymethod.as_ref\" class=\"fn\">as_ref</a>(self: &amp;<a class=\"struct\" href=\"idalib_sys/ffi/bindgen/root/struct.qbasic_block_t.html\" title=\"struct idalib_sys::ffi::bindgen::root::qbasic_block_t\">qbasic_block_t</a>) -&gt; &amp;<a class=\"struct\" href=\"idalib_sys/ffi/bindgen/root/struct.range_t.html\" title=\"struct idalib_sys::ffi::bindgen::root::range_t\">range_t</a></h4></section></summary><div class='docblock'>Converts this type into a shared reference of the (usually inferred) input type.</div></details></div></details>","AsRef<range_t>","idalib_sys::ffi::cxxbridge::qbasic_block_t","idalib_sys::ffix::qbasic_block_t"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Drop-for-qbasic_block_t\" class=\"impl\"><a href=\"#impl-Drop-for-qbasic_block_t\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.83.0/core/ops/drop/trait.Drop.html\" title=\"trait core::ops::drop::Drop\">Drop</a> for <a class=\"struct\" href=\"idalib_sys/ffi/bindgen/root/struct.qbasic_block_t.html\" title=\"struct idalib_sys::ffi::bindgen::root::qbasic_block_t\">qbasic_block_t</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.drop\" class=\"method trait-impl\"><a href=\"#method.drop\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.83.0/core/ops/drop/trait.Drop.html#tymethod.drop\" class=\"fn\">drop</a>(self: &amp;mut <a class=\"struct\" href=\"idalib_sys/ffi/bindgen/root/struct.qbasic_block_t.html\" title=\"struct idalib_sys::ffi::bindgen::root::qbasic_block_t\">qbasic_block_t</a>)</h4></section></summary><div class=\"docblock\"><p>Synthesized destructor.</p>\n</div></details></div></details>","Drop","idalib_sys::ffi::cxxbridge::qbasic_block_t","idalib_sys::ffix::qbasic_block_t"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-ExternType-for-qbasic_block_t\" class=\"impl\"><a href=\"#impl-ExternType-for-qbasic_block_t\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"cxx/extern_type/trait.ExternType.html\" title=\"trait cxx::extern_type::ExternType\">ExternType</a> for <a class=\"struct\" href=\"idalib_sys/ffi/bindgen/root/struct.qbasic_block_t.html\" title=\"struct idalib_sys::ffi::bindgen::root::qbasic_block_t\">qbasic_block_t</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle\" open><summary><section id=\"associatedtype.Id\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.Id\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a href=\"cxx/extern_type/trait.ExternType.html#associatedtype.Id\" class=\"associatedtype\">Id</a> = (<a class=\"enum\" href=\"cxx/enum.q.html\" title=\"enum cxx::q\">q</a>, <a class=\"enum\" href=\"cxx/enum.b.html\" title=\"enum cxx::b\">b</a>, <a class=\"enum\" href=\"cxx/enum.a.html\" title=\"enum cxx::a\">a</a>, <a class=\"enum\" href=\"cxx/enum.s.html\" title=\"enum cxx::s\">s</a>, <a class=\"enum\" href=\"cxx/enum.i.html\" title=\"enum cxx::i\">i</a>, <a class=\"enum\" href=\"cxx/enum.c.html\" title=\"enum cxx::c\">c</a>, <a class=\"enum\" href=\"cxx/enum.__.html\" title=\"enum cxx::__\">__</a>, <a class=\"enum\" href=\"cxx/enum.b.html\" title=\"enum cxx::b\">b</a>, <a class=\"enum\" href=\"cxx/enum.l.html\" title=\"enum cxx::l\">l</a>, <a class=\"enum\" href=\"cxx/enum.o.html\" title=\"enum cxx::o\">o</a>, <a class=\"enum\" href=\"cxx/enum.c.html\" title=\"enum cxx::c\">c</a>, <a class=\"enum\" href=\"cxx/enum.k.html\" title=\"enum cxx::k\">k</a>, <a class=\"enum\" href=\"cxx/enum.__.html\" title=\"enum cxx::__\">__</a>, <a class=\"enum\" href=\"cxx/enum.t.html\" title=\"enum cxx::t\">t</a>)</h4></section></summary><div class='docblock'>A type-level representation of the type’s C++ namespace and type name. <a href=\"cxx/extern_type/trait.ExternType.html#associatedtype.Id\">Read more</a></div></details><details class=\"toggle\" open><summary><section id=\"associatedtype.Kind\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.Kind\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a href=\"cxx/extern_type/trait.ExternType.html#associatedtype.Kind\" class=\"associatedtype\">Kind</a> = <a class=\"enum\" href=\"cxx/extern_type/kind/enum.Opaque.html\" title=\"enum cxx::extern_type::kind::Opaque\">Opaque</a></h4></section></summary><div class='docblock'>Either <a href=\"cxx/extern_type/kind/enum.Opaque.html\" title=\"enum cxx::extern_type::kind::Opaque\"><code>cxx::kind::Opaque</code></a> or <a href=\"cxx/extern_type/kind/enum.Trivial.html\" title=\"enum cxx::extern_type::kind::Trivial\"><code>cxx::kind::Trivial</code></a>. <a href=\"cxx/extern_type/trait.ExternType.html#associatedtype.Kind\">Read more</a></div></details></div></details>","ExternType","idalib_sys::ffi::cxxbridge::qbasic_block_t","idalib_sys::ffix::qbasic_block_t"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-MakeCppStorage-for-qbasic_block_t\" class=\"impl\"><a href=\"#impl-MakeCppStorage-for-qbasic_block_t\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"moveit/cxx_support/trait.MakeCppStorage.html\" title=\"trait moveit::cxx_support::MakeCppStorage\">MakeCppStorage</a> for <a class=\"struct\" href=\"idalib_sys/ffi/bindgen/root/struct.qbasic_block_t.html\" title=\"struct idalib_sys::ffi::bindgen::root::qbasic_block_t\">qbasic_block_t</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.allocate_uninitialized_cpp_storage\" class=\"method trait-impl\"><a href=\"#method.allocate_uninitialized_cpp_storage\" class=\"anchor\">§</a><h4 class=\"code-header\">unsafe fn <a href=\"moveit/cxx_support/trait.MakeCppStorage.html#tymethod.allocate_uninitialized_cpp_storage\" class=\"fn\">allocate_uninitialized_cpp_storage</a>() -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.83.0/std/primitive.pointer.html\">*mut </a><a class=\"struct\" href=\"idalib_sys/ffi/bindgen/root/struct.qbasic_block_t.html\" title=\"struct idalib_sys::ffi::bindgen::root::qbasic_block_t\">qbasic_block_t</a></h4></section></summary><div class='docblock'>Allocates heap space for this type in C++ and return a pointer\nto that space, but do not initialize that space (i.e. do not\nyet call a constructor). <a href=\"moveit/cxx_support/trait.MakeCppStorage.html#tymethod.allocate_uninitialized_cpp_storage\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.free_uninitialized_cpp_storage\" class=\"method trait-impl\"><a href=\"#method.free_uninitialized_cpp_storage\" class=\"anchor\">§</a><h4 class=\"code-header\">unsafe fn <a href=\"moveit/cxx_support/trait.MakeCppStorage.html#tymethod.free_uninitialized_cpp_storage\" class=\"fn\">free_uninitialized_cpp_storage</a>(arg0: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.83.0/std/primitive.pointer.html\">*mut </a><a class=\"struct\" href=\"idalib_sys/ffi/bindgen/root/struct.qbasic_block_t.html\" title=\"struct idalib_sys::ffi::bindgen::root::qbasic_block_t\">qbasic_block_t</a>)</h4></section></summary><div class='docblock'>Frees a C++ allocation which has not yet\nhad a constructor called. <a href=\"moveit/cxx_support/trait.MakeCppStorage.html#tymethod.free_uninitialized_cpp_storage\">Read more</a></div></details></div></details>","MakeCppStorage","idalib_sys::ffi::cxxbridge::qbasic_block_t","idalib_sys::ffix::qbasic_block_t"],["<section id=\"impl-SharedPtrTarget-for-qbasic_block_t\" class=\"impl\"><a href=\"#impl-SharedPtrTarget-for-qbasic_block_t\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"cxx/shared_ptr/trait.SharedPtrTarget.html\" title=\"trait cxx::shared_ptr::SharedPtrTarget\">SharedPtrTarget</a> for <a class=\"struct\" href=\"idalib_sys/ffi/bindgen/root/struct.qbasic_block_t.html\" title=\"struct idalib_sys::ffi::bindgen::root::qbasic_block_t\">qbasic_block_t</a></h3></section>","SharedPtrTarget","idalib_sys::ffi::cxxbridge::qbasic_block_t","idalib_sys::ffix::qbasic_block_t"],["<section id=\"impl-UniquePtrTarget-for-qbasic_block_t\" class=\"impl\"><a href=\"#impl-UniquePtrTarget-for-qbasic_block_t\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"cxx/unique_ptr/trait.UniquePtrTarget.html\" title=\"trait cxx::unique_ptr::UniquePtrTarget\">UniquePtrTarget</a> for <a class=\"struct\" href=\"idalib_sys/ffi/bindgen/root/struct.qbasic_block_t.html\" title=\"struct idalib_sys::ffi::bindgen::root::qbasic_block_t\">qbasic_block_t</a></h3></section>","UniquePtrTarget","idalib_sys::ffi::cxxbridge::qbasic_block_t","idalib_sys::ffix::qbasic_block_t"],["<section id=\"impl-WeakPtrTarget-for-qbasic_block_t\" class=\"impl\"><a href=\"#impl-WeakPtrTarget-for-qbasic_block_t\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"cxx/weak_ptr/trait.WeakPtrTarget.html\" title=\"trait cxx::weak_ptr::WeakPtrTarget\">WeakPtrTarget</a> for <a class=\"struct\" href=\"idalib_sys/ffi/bindgen/root/struct.qbasic_block_t.html\" title=\"struct idalib_sys::ffi::bindgen::root::qbasic_block_t\">qbasic_block_t</a></h3></section>","WeakPtrTarget","idalib_sys::ffi::cxxbridge::qbasic_block_t","idalib_sys::ffix::qbasic_block_t"]]]]);
    if (window.register_type_impls) {
        window.register_type_impls(type_impls);
    } else {
        window.pending_type_impls = type_impls;
    }
})()
//{"start":55,"fragment_lengths":[10433]}