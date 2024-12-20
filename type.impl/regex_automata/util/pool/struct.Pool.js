(function() {
    var type_impls = Object.fromEntries([["regex_automata",[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Debug-for-Pool%3CT,+F%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/regex_automata/util/pool.rs.html#186-190\">source</a><a href=\"#impl-Debug-for-Pool%3CT,+F%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.83.0/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a>, F&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.83.0/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> for <a class=\"struct\" href=\"regex_automata/util/pool/struct.Pool.html\" title=\"struct regex_automata::util::pool::Pool\">Pool</a>&lt;T, F&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.fmt\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/regex_automata/util/pool.rs.html#187-189\">source</a><a href=\"#method.fmt\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.83.0/core/fmt/trait.Debug.html#tymethod.fmt\" class=\"fn\">fmt</a>(&amp;self, f: &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/1.83.0/core/fmt/struct.Formatter.html\" title=\"struct core::fmt::Formatter\">Formatter</a>&lt;'_&gt;) -&gt; <a class=\"type\" href=\"https://doc.rust-lang.org/1.83.0/core/fmt/type.Result.html\" title=\"type core::fmt::Result\">Result</a></h4></section></summary><div class='docblock'>Formats the value using the given formatter. <a href=\"https://doc.rust-lang.org/1.83.0/core/fmt/trait.Debug.html#tymethod.fmt\">Read more</a></div></details></div></details>","Debug","regex_automata::meta::regex::CachePool"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Pool%3CT,+F%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/regex_automata/util/pool.rs.html#156-162\">source</a><a href=\"#impl-Pool%3CT,+F%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T, F&gt; <a class=\"struct\" href=\"regex_automata/util/pool/struct.Pool.html\" title=\"struct regex_automata::util::pool::Pool\">Pool</a>&lt;T, F&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.new\" class=\"method\"><a class=\"src rightside\" href=\"src/regex_automata/util/pool.rs.html#159-161\">source</a><h4 class=\"code-header\">pub fn <a href=\"regex_automata/util/pool/struct.Pool.html#tymethod.new\" class=\"fn\">new</a>(create: F) -&gt; <a class=\"struct\" href=\"regex_automata/util/pool/struct.Pool.html\" title=\"struct regex_automata::util::pool::Pool\">Pool</a>&lt;T, F&gt;</h4></section></summary><div class=\"docblock\"><p>Create a new pool. The given closure is used to create values in\nthe pool when necessary.</p>\n</div></details></div></details>",0,"regex_automata::meta::regex::CachePool"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Pool%3CT,+F%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/regex_automata/util/pool.rs.html#164-184\">source</a><a href=\"#impl-Pool%3CT,+F%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.83.0/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>, F: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.83.0/core/ops/function/trait.Fn.html\" title=\"trait core::ops::function::Fn\">Fn</a>() -&gt; T&gt; <a class=\"struct\" href=\"regex_automata/util/pool/struct.Pool.html\" title=\"struct regex_automata::util::pool::Pool\">Pool</a>&lt;T, F&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.get\" class=\"method\"><a class=\"src rightside\" href=\"src/regex_automata/util/pool.rs.html#181-183\">source</a><h4 class=\"code-header\">pub fn <a href=\"regex_automata/util/pool/struct.Pool.html#tymethod.get\" class=\"fn\">get</a>(&amp;self) -&gt; <a class=\"struct\" href=\"regex_automata/util/pool/struct.PoolGuard.html\" title=\"struct regex_automata::util::pool::PoolGuard\">PoolGuard</a>&lt;'_, T, F&gt;</h4></section></summary><div class=\"docblock\"><p>Get a value from the pool. The caller is guaranteed to have\nexclusive access to the given value. Namely, it is guaranteed that\nthis will never return a value that was returned by another call to\n<code>get</code> but was not put back into the pool.</p>\n<p>When the guard goes out of scope and its destructor is called, then\nit will automatically be put back into the pool. Alternatively,\n<a href=\"regex_automata/util/pool/struct.PoolGuard.html#method.put\" title=\"associated function regex_automata::util::pool::PoolGuard::put\"><code>PoolGuard::put</code></a> may be used to explicitly put it back in the pool\nwithout relying on its destructor.</p>\n<p>Note that there is no guarantee provided about which value in the\npool is returned. That is, calling get, dropping the guard (causing\nthe value to go back into the pool) and then calling get again is\n<em>not</em> guaranteed to return the same value received in the first <code>get</code>\ncall.</p>\n</div></details></div></details>",0,"regex_automata::meta::regex::CachePool"]]]]);
    if (window.register_type_impls) {
        window.register_type_impls(type_impls);
    } else {
        window.pending_type_impls = type_impls;
    }
})()
//{"start":55,"fragment_lengths":[5319]}