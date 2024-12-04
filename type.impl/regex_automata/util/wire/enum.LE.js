(function() {
    var type_impls = Object.fromEntries([["regex_automata",[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Endian-for-LE\" class=\"impl\"><a class=\"src rightside\" href=\"src/regex_automata/util/wire.rs.html#882-894\">source</a><a href=\"#impl-Endian-for-LE\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"regex_automata/util/wire/trait.Endian.html\" title=\"trait regex_automata::util::wire::Endian\">Endian</a> for <a class=\"enum\" href=\"regex_automata/util/wire/enum.LE.html\" title=\"enum regex_automata::util::wire::LE\">LE</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.write_u16\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/regex_automata/util/wire.rs.html#883-885\">source</a><a href=\"#method.write_u16\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"regex_automata/util/wire/trait.Endian.html#tymethod.write_u16\" class=\"fn\">write_u16</a>(n: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/std/primitive.u16.html\">u16</a>, dst: &amp;mut [<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/std/primitive.u8.html\">u8</a>])</h4></section></summary><div class='docblock'>Writes a u16 to the given destination buffer in a particular\nendianness. If the destination buffer has a length smaller than 2, then\nthis panics.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.write_u32\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/regex_automata/util/wire.rs.html#887-889\">source</a><a href=\"#method.write_u32\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"regex_automata/util/wire/trait.Endian.html#tymethod.write_u32\" class=\"fn\">write_u32</a>(n: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/std/primitive.u32.html\">u32</a>, dst: &amp;mut [<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/std/primitive.u8.html\">u8</a>])</h4></section></summary><div class='docblock'>Writes a u32 to the given destination buffer in a particular\nendianness. If the destination buffer has a length smaller than 4, then\nthis panics.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.write_u128\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/regex_automata/util/wire.rs.html#891-893\">source</a><a href=\"#method.write_u128\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"regex_automata/util/wire/trait.Endian.html#tymethod.write_u128\" class=\"fn\">write_u128</a>(n: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/std/primitive.u128.html\">u128</a>, dst: &amp;mut [<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/std/primitive.u8.html\">u8</a>])</h4></section></summary><div class='docblock'>Writes a u128 to the given destination buffer in a particular\nendianness. If the destination buffer has a length smaller than 16,\nthen this panics.</div></details></div></details>","Endian","regex_automata::util::wire::NE"]]]]);
    if (window.register_type_impls) {
        window.register_type_impls(type_impls);
    } else {
        window.pending_type_impls = type_impls;
    }
})()
//{"start":55,"fragment_lengths":[3110]}