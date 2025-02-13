(function() {
    var type_impls = Object.fromEntries([["ucd_trie",[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Clone-for-TrieSetSlice%3C'a%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/ucd_trie/lib.rs.html#46\">Source</a><a href=\"#impl-Clone-for-TrieSetSlice%3C'a%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"ucd_trie/struct.TrieSetSlice.html\" title=\"struct ucd_trie::TrieSetSlice\">TrieSetSlice</a>&lt;'a&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/ucd_trie/lib.rs.html#46\">Source</a><a href=\"#method.clone\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.84.1/core/clone/trait.Clone.html#tymethod.clone\" class=\"fn\">clone</a>(&amp;self) -&gt; <a class=\"struct\" href=\"ucd_trie/struct.TrieSetSlice.html\" title=\"struct ucd_trie::TrieSetSlice\">TrieSetSlice</a>&lt;'a&gt;</h4></section></summary><div class='docblock'>Returns a copy of the value. <a href=\"https://doc.rust-lang.org/1.84.1/core/clone/trait.Clone.html#tymethod.clone\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone_from\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.84.1/src/core/clone.rs.html#174\">Source</a></span><a href=\"#method.clone_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.84.1/core/clone/trait.Clone.html#method.clone_from\" class=\"fn\">clone_from</a>(&amp;mut self, source: &amp;Self)</h4></section></summary><div class='docblock'>Performs copy-assignment from <code>source</code>. <a href=\"https://doc.rust-lang.org/1.84.1/core/clone/trait.Clone.html#method.clone_from\">Read more</a></div></details></div></details>","Clone","ucd_trie::TrieSet"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Debug-for-TrieSetSlice%3C'a%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/ucd_trie/lib.rs.html#68-72\">Source</a><a href=\"#impl-Debug-for-TrieSetSlice%3C'a%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.1/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> for <a class=\"struct\" href=\"ucd_trie/struct.TrieSetSlice.html\" title=\"struct ucd_trie::TrieSetSlice\">TrieSetSlice</a>&lt;'a&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.fmt\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/ucd_trie/lib.rs.html#69-71\">Source</a><a href=\"#method.fmt\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.84.1/core/fmt/trait.Debug.html#tymethod.fmt\" class=\"fn\">fmt</a>(&amp;self, f: &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/1.84.1/core/fmt/struct.Formatter.html\" title=\"struct core::fmt::Formatter\">Formatter</a>&lt;'_&gt;) -&gt; <a class=\"type\" href=\"https://doc.rust-lang.org/1.84.1/core/fmt/type.Result.html\" title=\"type core::fmt::Result\">Result</a></h4></section></summary><div class='docblock'>Formats the value using the given formatter. <a href=\"https://doc.rust-lang.org/1.84.1/core/fmt/trait.Debug.html#tymethod.fmt\">Read more</a></div></details></div></details>","Debug","ucd_trie::TrieSet"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-TrieSetSlice%3C'a%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/ucd_trie/lib.rs.html#74-117\">Source</a><a href=\"#impl-TrieSetSlice%3C'a%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;'a&gt; <a class=\"struct\" href=\"ucd_trie/struct.TrieSetSlice.html\" title=\"struct ucd_trie::TrieSetSlice\">TrieSetSlice</a>&lt;'a&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.contains_char\" class=\"method\"><a class=\"src rightside\" href=\"src/ucd_trie/lib.rs.html#77-79\">Source</a><h4 class=\"code-header\">pub fn <a href=\"ucd_trie/struct.TrieSetSlice.html#tymethod.contains_char\" class=\"fn\">contains_char</a>(&amp;self, c: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.char.html\">char</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.bool.html\">bool</a></h4></section></summary><div class=\"docblock\"><p>Returns true if and only if the given Unicode scalar value is in this\nset.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.contains_u32\" class=\"method\"><a class=\"src rightside\" href=\"src/ucd_trie/lib.rs.html#85-90\">Source</a><h4 class=\"code-header\">pub fn <a href=\"ucd_trie/struct.TrieSetSlice.html#tymethod.contains_u32\" class=\"fn\">contains_u32</a>(&amp;self, cp: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.u32.html\">u32</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.bool.html\">bool</a></h4></section></summary><div class=\"docblock\"><p>Returns true if and only if the given codepoint is in this set.</p>\n<p>If the given value exceeds the codepoint range (i.e., it’s greater\nthan <code>0x10FFFF</code>), then this returns false.</p>\n</div></details><section id=\"method.contains\" class=\"method\"><a class=\"src rightside\" href=\"src/ucd_trie/lib.rs.html#93-111\">Source</a><h4 class=\"code-header\">pub(crate) fn <a href=\"ucd_trie/struct.TrieSetSlice.html#tymethod.contains\" class=\"fn\">contains</a>(&amp;self, cp: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.usize.html\">usize</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.bool.html\">bool</a></h4></section><section id=\"method.chunk_contains\" class=\"method\"><a class=\"src rightside\" href=\"src/ucd_trie/lib.rs.html#114-116\">Source</a><h4 class=\"code-header\">pub(crate) fn <a href=\"ucd_trie/struct.TrieSetSlice.html#tymethod.chunk_contains\" class=\"fn\">chunk_contains</a>(&amp;self, cp: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.usize.html\">usize</a>, chunk: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.u64.html\">u64</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.bool.html\">bool</a></h4></section></div></details>",0,"ucd_trie::TrieSet"],["<section id=\"impl-Copy-for-TrieSetSlice%3C'a%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/ucd_trie/lib.rs.html#46\">Source</a><a href=\"#impl-Copy-for-TrieSetSlice%3C'a%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.1/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> for <a class=\"struct\" href=\"ucd_trie/struct.TrieSetSlice.html\" title=\"struct ucd_trie::TrieSetSlice\">TrieSetSlice</a>&lt;'a&gt;</h3></section>","Copy","ucd_trie::TrieSet"]]]]);
    if (window.register_type_impls) {
        window.register_type_impls(type_impls);
    } else {
        window.pending_type_impls = type_impls;
    }
})()
//{"start":55,"fragment_lengths":[7425]}