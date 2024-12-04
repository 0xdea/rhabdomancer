(function() {
    var type_impls = Object.fromEntries([["regex_syntax",[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Default-for-%26%5BT%5D\" class=\"impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.82.0/src/core/slice/mod.rs.html#4816\">source</a></span><a href=\"#impl-Default-for-%26%5BT%5D\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for &amp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/std/primitive.slice.html\">[T]</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.default\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"https://doc.rust-lang.org/1.82.0/src/core/slice/mod.rs.html#4818\">source</a><a href=\"#method.default\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html#tymethod.default\" class=\"fn\">default</a>() -&gt; &amp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/std/primitive.slice.html\">[T]</a></h4></section></summary><div class=\"docblock\"><p>Creates an empty slice.</p>\n</div></details></div></details>","Default","regex_syntax::unicode::Range","regex_syntax::unicode::PropertyValues"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-IntoIterator-for-%26%5BT%5D\" class=\"impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.82.0/src/core/slice/iter.rs.html#21\">source</a></span><a href=\"#impl-IntoIterator-for-%26%5BT%5D\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;'a, T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/iter/traits/collect/trait.IntoIterator.html\" title=\"trait core::iter::traits::collect::IntoIterator\">IntoIterator</a> for &amp;'a <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/std/primitive.slice.html\">[T]</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle\" open><summary><section id=\"associatedtype.Item\" class=\"associatedtype trait-impl\"><a class=\"src rightside\" href=\"https://doc.rust-lang.org/1.82.0/src/core/slice/iter.rs.html#22\">source</a><a href=\"#associatedtype.Item\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a href=\"https://doc.rust-lang.org/1.82.0/core/iter/traits/collect/trait.IntoIterator.html#associatedtype.Item\" class=\"associatedtype\">Item</a> = <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/std/primitive.reference.html\">&amp;'a T</a></h4></section></summary><div class='docblock'>The type of the elements being iterated over.</div></details><details class=\"toggle\" open><summary><section id=\"associatedtype.IntoIter\" class=\"associatedtype trait-impl\"><a class=\"src rightside\" href=\"https://doc.rust-lang.org/1.82.0/src/core/slice/iter.rs.html#23\">source</a><a href=\"#associatedtype.IntoIter\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a href=\"https://doc.rust-lang.org/1.82.0/core/iter/traits/collect/trait.IntoIterator.html#associatedtype.IntoIter\" class=\"associatedtype\">IntoIter</a> = <a class=\"struct\" href=\"https://doc.rust-lang.org/1.82.0/core/slice/iter/struct.Iter.html\" title=\"struct core::slice::iter::Iter\">Iter</a>&lt;'a, T&gt;</h4></section></summary><div class='docblock'>Which kind of iterator are we turning this into?</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.into_iter\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"https://doc.rust-lang.org/1.82.0/src/core/slice/iter.rs.html#25\">source</a><a href=\"#method.into_iter\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.82.0/core/iter/traits/collect/trait.IntoIterator.html#tymethod.into_iter\" class=\"fn\">into_iter</a>(self) -&gt; <a class=\"struct\" href=\"https://doc.rust-lang.org/1.82.0/core/slice/iter/struct.Iter.html\" title=\"struct core::slice::iter::Iter\">Iter</a>&lt;'a, T&gt;</h4></section></summary><div class='docblock'>Creates an iterator from a value. <a href=\"https://doc.rust-lang.org/1.82.0/core/iter/traits/collect/trait.IntoIterator.html#tymethod.into_iter\">Read more</a></div></details></div></details>","IntoIterator","regex_syntax::unicode::Range","regex_syntax::unicode::PropertyValues"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-PartialEq%3C%5BU;+N%5D%3E-for-%26%5BT%5D\" class=\"impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.82.0/src/core/array/equality.rs.html#80-82\">source</a></span><a href=\"#impl-PartialEq%3C%5BU;+N%5D%3E-for-%26%5BT%5D\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T, U, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/std/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/std/primitive.array.html\">[U; N]</a>&gt; for &amp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/std/primitive.slice.html\">[T]</a><div class=\"where\">where\n    T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a>&lt;U&gt;,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.eq\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"https://doc.rust-lang.org/1.82.0/src/core/array/equality.rs.html#85\">source</a><a href=\"#method.eq\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.82.0/core/cmp/trait.PartialEq.html#tymethod.eq\" class=\"fn\">eq</a>(&amp;self, other: &amp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/std/primitive.array.html\">[U; N]</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>Tests for <code>self</code> and <code>other</code> values to be equal, and is used by <code>==</code>.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ne\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"https://doc.rust-lang.org/1.82.0/src/core/array/equality.rs.html#89\">source</a><a href=\"#method.ne\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.82.0/core/cmp/trait.PartialEq.html#method.ne\" class=\"fn\">ne</a>(&amp;self, other: &amp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/std/primitive.array.html\">[U; N]</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>Tests for <code>!=</code>. The default implementation is almost always sufficient,\nand should not be overridden without very good reason.</div></details></div></details>","PartialEq<[U; N]>","regex_syntax::unicode::Range","regex_syntax::unicode::PropertyValues"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-PartialEq%3CVec%3CU,+A%3E%3E-for-%26%5BT%5D\" class=\"impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.46.0\">1.46.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.82.0/src/alloc/vec/partial_eq.rs.html#25\">source</a></span><a href=\"#impl-PartialEq%3CVec%3CU,+A%3E%3E-for-%26%5BT%5D\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T, U, A&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/1.82.0/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;U, A&gt;&gt; for &amp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/std/primitive.slice.html\">[T]</a><div class=\"where\">where\n    A: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/alloc/trait.Allocator.html\" title=\"trait core::alloc::Allocator\">Allocator</a>,\n    T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a>&lt;U&gt;,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.eq\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"https://doc.rust-lang.org/1.82.0/src/alloc/vec/partial_eq.rs.html#25\">source</a><a href=\"#method.eq\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.82.0/core/cmp/trait.PartialEq.html#tymethod.eq\" class=\"fn\">eq</a>(&amp;self, other: &amp;<a class=\"struct\" href=\"https://doc.rust-lang.org/1.82.0/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;U, A&gt;) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>Tests for <code>self</code> and <code>other</code> values to be equal, and is used by <code>==</code>.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ne\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"https://doc.rust-lang.org/1.82.0/src/alloc/vec/partial_eq.rs.html#25\">source</a><a href=\"#method.ne\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.82.0/core/cmp/trait.PartialEq.html#method.ne\" class=\"fn\">ne</a>(&amp;self, other: &amp;<a class=\"struct\" href=\"https://doc.rust-lang.org/1.82.0/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;U, A&gt;) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>Tests for <code>!=</code>. The default implementation is almost always sufficient,\nand should not be overridden without very good reason.</div></details></div></details>","PartialEq<Vec<U, A>>","regex_syntax::unicode::Range","regex_syntax::unicode::PropertyValues"]]]]);
    if (window.register_type_impls) {
        window.register_type_impls(type_impls);
    } else {
        window.pending_type_impls = type_impls;
    }
})()
//{"start":55,"fragment_lengths":[10687]}