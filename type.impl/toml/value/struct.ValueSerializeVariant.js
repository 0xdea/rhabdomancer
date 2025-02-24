(function() {
    var type_impls = Object.fromEntries([["toml",[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-SerializeStructVariant-for-ValueSerializeVariant%3CValueSerializeMap%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/toml/value.rs.html#1506-1525\">Source</a><a href=\"#impl-SerializeStructVariant-for-ValueSerializeVariant%3CValueSerializeMap%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"serde/ser/trait.SerializeStructVariant.html\" title=\"trait serde::ser::SerializeStructVariant\">SerializeStructVariant</a> for <a class=\"struct\" href=\"toml/value/struct.ValueSerializeVariant.html\" title=\"struct toml::value::ValueSerializeVariant\">ValueSerializeVariant</a>&lt;<a class=\"struct\" href=\"toml/value/struct.ValueSerializeMap.html\" title=\"struct toml::value::ValueSerializeMap\">ValueSerializeMap</a>&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle\" open><summary><section id=\"associatedtype.Ok\" class=\"associatedtype trait-impl\"><a class=\"src rightside\" href=\"src/toml/value.rs.html#1507\">Source</a><a href=\"#associatedtype.Ok\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a href=\"serde/ser/trait.SerializeStructVariant.html#associatedtype.Ok\" class=\"associatedtype\">Ok</a> = <a class=\"enum\" href=\"toml/enum.Value.html\" title=\"enum toml::Value\">Value</a></h4></section></summary><div class='docblock'>Must match the <code>Ok</code> type of our <code>Serializer</code>.</div></details><details class=\"toggle\" open><summary><section id=\"associatedtype.Error\" class=\"associatedtype trait-impl\"><a class=\"src rightside\" href=\"src/toml/value.rs.html#1508\">Source</a><a href=\"#associatedtype.Error\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a href=\"serde/ser/trait.SerializeStructVariant.html#associatedtype.Error\" class=\"associatedtype\">Error</a> = <a class=\"struct\" href=\"toml/ser/struct.Error.html\" title=\"struct toml::ser::Error\">Error</a></h4></section></summary><div class='docblock'>Must match the <code>Error</code> type of our <code>Serializer</code>.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.serialize_field\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/toml/value.rs.html#1511-1516\">Source</a><a href=\"#method.serialize_field\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"serde/ser/trait.SerializeStructVariant.html#tymethod.serialize_field\" class=\"fn\">serialize_field</a>&lt;T&gt;(\n    &amp;mut self,\n    key: &amp;'static <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.str.html\">str</a>,\n    value: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.reference.html\">&amp;T</a>,\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.84.1/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.unit.html\">()</a>, Self::<a class=\"associatedtype\" href=\"serde/ser/trait.SerializeStructVariant.html#associatedtype.Error\" title=\"type serde::ser::SerializeStructVariant::Error\">Error</a>&gt;<div class=\"where\">where\n    T: <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> + ?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.1/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>,</div></h4></section></summary><div class='docblock'>Serialize a struct variant field.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.end\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/toml/value.rs.html#1519-1524\">Source</a><a href=\"#method.end\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"serde/ser/trait.SerializeStructVariant.html#tymethod.end\" class=\"fn\">end</a>(self) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.84.1/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;Self::<a class=\"associatedtype\" href=\"serde/ser/trait.SerializeStructVariant.html#associatedtype.Ok\" title=\"type serde::ser::SerializeStructVariant::Ok\">Ok</a>, Self::<a class=\"associatedtype\" href=\"serde/ser/trait.SerializeStructVariant.html#associatedtype.Error\" title=\"type serde::ser::SerializeStructVariant::Error\">Error</a>&gt;</h4></section></summary><div class='docblock'>Finish serializing a struct variant.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.skip_field\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/serde/ser/mod.rs.html#1936\">Source</a><a href=\"#method.skip_field\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"serde/ser/trait.SerializeStructVariant.html#method.skip_field\" class=\"fn\">skip_field</a>(&amp;mut self, key: &amp;'static <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.str.html\">str</a>) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.84.1/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.unit.html\">()</a>, Self::<a class=\"associatedtype\" href=\"serde/ser/trait.SerializeStructVariant.html#associatedtype.Error\" title=\"type serde::ser::SerializeStructVariant::Error\">Error</a>&gt;</h4></section></summary><div class='docblock'>Indicate that a struct variant field has been skipped. <a href=\"serde/ser/trait.SerializeStructVariant.html#method.skip_field\">Read more</a></div></details></div></details>","SerializeStructVariant","toml::value::ValueSerializeStructVariant"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-SerializeTupleVariant-for-ValueSerializeVariant%3CValueSerializeVec%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/toml/value.rs.html#1487-1504\">Source</a><a href=\"#impl-SerializeTupleVariant-for-ValueSerializeVariant%3CValueSerializeVec%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"serde/ser/trait.SerializeTupleVariant.html\" title=\"trait serde::ser::SerializeTupleVariant\">SerializeTupleVariant</a> for <a class=\"struct\" href=\"toml/value/struct.ValueSerializeVariant.html\" title=\"struct toml::value::ValueSerializeVariant\">ValueSerializeVariant</a>&lt;<a class=\"struct\" href=\"toml/value/struct.ValueSerializeVec.html\" title=\"struct toml::value::ValueSerializeVec\">ValueSerializeVec</a>&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle\" open><summary><section id=\"associatedtype.Ok\" class=\"associatedtype trait-impl\"><a class=\"src rightside\" href=\"src/toml/value.rs.html#1488\">Source</a><a href=\"#associatedtype.Ok\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a href=\"serde/ser/trait.SerializeTupleVariant.html#associatedtype.Ok\" class=\"associatedtype\">Ok</a> = <a class=\"enum\" href=\"toml/enum.Value.html\" title=\"enum toml::Value\">Value</a></h4></section></summary><div class='docblock'>Must match the <code>Ok</code> type of our <code>Serializer</code>.</div></details><details class=\"toggle\" open><summary><section id=\"associatedtype.Error\" class=\"associatedtype trait-impl\"><a class=\"src rightside\" href=\"src/toml/value.rs.html#1489\">Source</a><a href=\"#associatedtype.Error\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a href=\"serde/ser/trait.SerializeTupleVariant.html#associatedtype.Error\" class=\"associatedtype\">Error</a> = <a class=\"struct\" href=\"toml/ser/struct.Error.html\" title=\"struct toml::ser::Error\">Error</a></h4></section></summary><div class='docblock'>Must match the <code>Error</code> type of our <code>Serializer</code>.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.serialize_field\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/toml/value.rs.html#1491-1496\">Source</a><a href=\"#method.serialize_field\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"serde/ser/trait.SerializeTupleVariant.html#tymethod.serialize_field\" class=\"fn\">serialize_field</a>&lt;T&gt;(&amp;mut self, value: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.reference.html\">&amp;T</a>) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.84.1/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.unit.html\">()</a>, Self::<a class=\"associatedtype\" href=\"serde/ser/trait.SerializeTupleVariant.html#associatedtype.Error\" title=\"type serde::ser::SerializeTupleVariant::Error\">Error</a>&gt;<div class=\"where\">where\n    T: <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> + ?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.1/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>,</div></h4></section></summary><div class='docblock'>Serialize a tuple variant field.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.end\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/toml/value.rs.html#1498-1503\">Source</a><a href=\"#method.end\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"serde/ser/trait.SerializeTupleVariant.html#tymethod.end\" class=\"fn\">end</a>(self) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.84.1/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;Self::<a class=\"associatedtype\" href=\"serde/ser/trait.SerializeTupleVariant.html#associatedtype.Ok\" title=\"type serde::ser::SerializeTupleVariant::Ok\">Ok</a>, Self::<a class=\"associatedtype\" href=\"serde/ser/trait.SerializeTupleVariant.html#associatedtype.Error\" title=\"type serde::ser::SerializeTupleVariant::Error\">Error</a>&gt;</h4></section></summary><div class='docblock'>Finish serializing a tuple variant.</div></details></div></details>","SerializeTupleVariant","toml::value::ValueSerializeTupleVariant"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-ValueSerializeVariant%3CValueSerializeMap%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/toml/value.rs.html#1473-1485\">Source</a><a href=\"#impl-ValueSerializeVariant%3CValueSerializeMap%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"struct\" href=\"toml/value/struct.ValueSerializeVariant.html\" title=\"struct toml::value::ValueSerializeVariant\">ValueSerializeVariant</a>&lt;<a class=\"struct\" href=\"toml/value/struct.ValueSerializeMap.html\" title=\"struct toml::value::ValueSerializeMap\">ValueSerializeMap</a>&gt;</h3></section></summary><div class=\"impl-items\"><section id=\"method.struct_\" class=\"method\"><a class=\"src rightside\" href=\"src/toml/value.rs.html#1474-1484\">Source</a><h4 class=\"code-header\">pub(crate) fn <a href=\"toml/value/struct.ValueSerializeVariant.html#tymethod.struct_\" class=\"fn\">struct_</a>(variant: &amp;'static <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.str.html\">str</a>, len: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.usize.html\">usize</a>) -&gt; Self</h4></section></div></details>",0,"toml::value::ValueSerializeStructVariant"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-ValueSerializeVariant%3CValueSerializeVec%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/toml/value.rs.html#1462-1471\">Source</a><a href=\"#impl-ValueSerializeVariant%3CValueSerializeVec%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"struct\" href=\"toml/value/struct.ValueSerializeVariant.html\" title=\"struct toml::value::ValueSerializeVariant\">ValueSerializeVariant</a>&lt;<a class=\"struct\" href=\"toml/value/struct.ValueSerializeVec.html\" title=\"struct toml::value::ValueSerializeVec\">ValueSerializeVec</a>&gt;</h3></section></summary><div class=\"impl-items\"><section id=\"method.tuple\" class=\"method\"><a class=\"src rightside\" href=\"src/toml/value.rs.html#1463-1470\">Source</a><h4 class=\"code-header\">pub(crate) fn <a href=\"toml/value/struct.ValueSerializeVariant.html#tymethod.tuple\" class=\"fn\">tuple</a>(variant: &amp;'static <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.str.html\">str</a>, len: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.usize.html\">usize</a>) -&gt; Self</h4></section></div></details>",0,"toml::value::ValueSerializeTupleVariant"]]]]);
    if (window.register_type_impls) {
        window.register_type_impls(type_impls);
    } else {
        window.pending_type_impls = type_impls;
    }
})()
//{"start":55,"fragment_lengths":[12767]}