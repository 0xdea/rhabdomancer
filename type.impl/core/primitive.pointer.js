(function() {
    var type_impls = Object.fromEntries([["libc",[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Clone-for-*mut+T\" class=\"impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.82.0/src/core/clone.rs.html#357\">source</a></span><a href=\"#impl-Clone-for-*mut+T\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T&gt; <a class=\"trait\" href=\"libc/prelude/trait.Clone.html\" title=\"trait libc::prelude::Clone\">Clone</a> for <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.pointer.html\">*mut T</a><div class=\"where\">where\n    T: ?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"https://doc.rust-lang.org/1.82.0/src/core/clone.rs.html#359\">source</a><a href=\"#method.clone\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"libc/prelude/trait.Clone.html#tymethod.clone\" class=\"fn\">clone</a>(&amp;self) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.pointer.html\">*mut T</a></h4></section></summary><div class='docblock'>Returns a copy of the value. <a href=\"libc/prelude/trait.Clone.html#tymethod.clone\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone_from\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.82.0/src/core/clone.rs.html#174\">source</a></span><a href=\"#method.clone_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"libc/prelude/trait.Clone.html#method.clone_from\" class=\"fn\">clone_from</a>(&amp;mut self, source: &amp;Self)</h4></section></summary><div class='docblock'>Performs copy-assignment from <code>source</code>. <a href=\"libc/prelude/trait.Clone.html#method.clone_from\">Read more</a></div></details></div></details>","Clone","libc::unix::linux_like::linux::iconv_t","libc::unix::linux_like::timer_t","libc::unix::locale_t"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Debug-for-*mut+T\" class=\"impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.82.0/src/core/fmt/mod.rs.html#2576\">source</a></span><a href=\"#impl-Debug-for-*mut+T\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T&gt; <a class=\"trait\" href=\"libc/prelude/fmt/trait.Debug.html\" title=\"trait libc::prelude::fmt::Debug\">Debug</a> for <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.pointer.html\">*mut T</a><div class=\"where\">where\n    T: ?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.fmt\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"https://doc.rust-lang.org/1.82.0/src/core/fmt/mod.rs.html#2577\">source</a><a href=\"#method.fmt\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"libc/prelude/fmt/trait.Debug.html#tymethod.fmt\" class=\"fn\">fmt</a>(&amp;self, f: &amp;mut <a class=\"struct\" href=\"libc/prelude/fmt/struct.Formatter.html\" title=\"struct libc::prelude::fmt::Formatter\">Formatter</a>&lt;'_&gt;) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.82.0/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.unit.html\">()</a>, <a class=\"struct\" href=\"libc/prelude/fmt/struct.Error.html\" title=\"struct libc::prelude::fmt::Error\">Error</a>&gt;</h4></section></summary><div class='docblock'>Formats the value using the given formatter. <a href=\"libc/prelude/fmt/trait.Debug.html#tymethod.fmt\">Read more</a></div></details></div></details>","Debug","libc::unix::linux_like::linux::iconv_t","libc::unix::linux_like::timer_t","libc::unix::locale_t"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Hash-for-*mut+T\" class=\"impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.82.0/src/core/hash/mod.rs.html#973\">source</a></span><a href=\"#impl-Hash-for-*mut+T\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T&gt; <a class=\"trait\" href=\"libc/prelude/hash/trait.Hash.html\" title=\"trait libc::prelude::hash::Hash\">Hash</a> for <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.pointer.html\">*mut T</a><div class=\"where\">where\n    T: ?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.hash\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"https://doc.rust-lang.org/1.82.0/src/core/hash/mod.rs.html#975\">source</a><a href=\"#method.hash\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"libc/prelude/hash/trait.Hash.html#tymethod.hash\" class=\"fn\">hash</a>&lt;H&gt;(&amp;self, state: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.reference.html\">&amp;mut H</a>)<div class=\"where\">where\n    H: <a class=\"trait\" href=\"libc/prelude/hash/trait.Hasher.html\" title=\"trait libc::prelude::hash::Hasher\">Hasher</a>,</div></h4></section></summary><div class='docblock'>Feeds this value into the given <a href=\"libc/prelude/hash/trait.Hasher.html\" title=\"trait libc::prelude::hash::Hasher\"><code>Hasher</code></a>. <a href=\"libc/prelude/hash/trait.Hash.html#tymethod.hash\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.hash_slice\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.3.0\">1.3.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.82.0/src/core/hash/mod.rs.html#235-237\">source</a></span><a href=\"#method.hash_slice\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"libc/prelude/hash/trait.Hash.html#method.hash_slice\" class=\"fn\">hash_slice</a>&lt;H&gt;(data: &amp;[Self], state: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.reference.html\">&amp;mut H</a>)<div class=\"where\">where\n    H: <a class=\"trait\" href=\"libc/prelude/hash/trait.Hasher.html\" title=\"trait libc::prelude::hash::Hasher\">Hasher</a>,\n    Self: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>,</div></h4></section></summary><div class='docblock'>Feeds a slice of this type into the given <a href=\"libc/prelude/hash/trait.Hasher.html\" title=\"trait libc::prelude::hash::Hasher\"><code>Hasher</code></a>. <a href=\"libc/prelude/hash/trait.Hash.html#method.hash_slice\">Read more</a></div></details></div></details>","Hash","libc::unix::linux_like::linux::iconv_t","libc::unix::linux_like::timer_t","libc::unix::locale_t"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Pointer-for-*mut+T\" class=\"impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.82.0/src/core/fmt/mod.rs.html#2547\">source</a></span><a href=\"#impl-Pointer-for-*mut+T\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T&gt; <a class=\"trait\" href=\"libc/prelude/fmt/trait.Pointer.html\" title=\"trait libc::prelude::fmt::Pointer\">Pointer</a> for <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.pointer.html\">*mut T</a><div class=\"where\">where\n    T: ?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.fmt\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"https://doc.rust-lang.org/1.82.0/src/core/fmt/mod.rs.html#2548\">source</a><a href=\"#method.fmt\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"libc/prelude/fmt/trait.Pointer.html#tymethod.fmt\" class=\"fn\">fmt</a>(&amp;self, f: &amp;mut <a class=\"struct\" href=\"libc/prelude/fmt/struct.Formatter.html\" title=\"struct libc::prelude::fmt::Formatter\">Formatter</a>&lt;'_&gt;) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.82.0/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.unit.html\">()</a>, <a class=\"struct\" href=\"libc/prelude/fmt/struct.Error.html\" title=\"struct libc::prelude::fmt::Error\">Error</a>&gt;</h4></section></summary><div class='docblock'>Formats the value using the given formatter. <a href=\"libc/prelude/fmt/trait.Pointer.html#tymethod.fmt\">Read more</a></div></details></div></details>","Pointer","libc::unix::linux_like::linux::iconv_t","libc::unix::linux_like::timer_t","libc::unix::locale_t"],["<section id=\"impl-Copy-for-*mut+T\" class=\"impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.82.0/src/core/marker.rs.html#421-431\">source</a></span><a href=\"#impl-Copy-for-*mut+T\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T&gt; <a class=\"trait\" href=\"libc/prelude/trait.Copy.html\" title=\"trait libc::prelude::Copy\">Copy</a> for <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.pointer.html\">*mut T</a><div class=\"where\">where\n    T: ?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>,</div></h3></section>","Copy","libc::unix::linux_like::linux::iconv_t","libc::unix::linux_like::timer_t","libc::unix::locale_t"],["<section id=\"impl-Send-for-*mut+T\" class=\"impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.82.0/src/core/marker.rs.html#90\">source</a></span><a href=\"#impl-Send-for-*mut+T\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T&gt; !<a class=\"trait\" href=\"libc/prelude/trait.Send.html\" title=\"trait libc::prelude::Send\">Send</a> for <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.pointer.html\">*mut T</a><div class=\"where\">where\n    T: ?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>,</div></h3></section>","Send","libc::unix::linux_like::linux::iconv_t","libc::unix::linux_like::timer_t","libc::unix::locale_t"],["<section id=\"impl-Sync-for-*mut+T\" class=\"impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.82.0/src/core/marker.rs.html#603\">source</a></span><a href=\"#impl-Sync-for-*mut+T\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T&gt; !<a class=\"trait\" href=\"libc/prelude/trait.Sync.html\" title=\"trait libc::prelude::Sync\">Sync</a> for <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.pointer.html\">*mut T</a><div class=\"where\">where\n    T: ?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>,</div></h3></section>","Sync","libc::unix::linux_like::linux::iconv_t","libc::unix::linux_like::timer_t","libc::unix::locale_t"]]]]);
    if (window.register_type_impls) {
        window.register_type_impls(type_impls);
    } else {
        window.pending_type_impls = type_impls;
    }
})()
//{"start":55,"fragment_lengths":[12380]}