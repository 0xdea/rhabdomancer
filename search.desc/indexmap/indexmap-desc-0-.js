searchState.loadedDescShard("indexmap", 0, "<code>IndexMap</code> is a hash table where the iteration order of the …\nKey equivalence trait.\nHash value newtype. Not larger than usize, since anything …\nThe error type for <code>try_reserve</code> methods.\nCompare self to <code>key</code> and return <code>true</code> if they are equal.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCreate an <code>IndexMap</code> from a list of key-value pairs\nCreate an <code>IndexSet</code> from a list of values\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\n<code>IndexMap</code> is a hash table where the iteration order of the …\nA hash set implemented using <code>IndexMap</code>\nA draining iterator over the entries of an <code>IndexMap</code>.\nEntry for an existing key-value pair in an <code>IndexMap</code> or a …\nA hash table where the iteration order of the key-value …\nA view into an occupied entry in an <code>IndexMap</code> obtained by …\nAn owning iterator over the entries of an <code>IndexMap</code>.\nAn owning iterator over the keys of an <code>IndexMap</code>.\nAn owning iterator over the values of an <code>IndexMap</code>.\nAn iterator over the entries of an <code>IndexMap</code>.\nA mutable iterator over the entries of an <code>IndexMap</code>.\nA mutable iterator over the entries of an <code>IndexMap</code>.\nAn iterator over the keys of an <code>IndexMap</code>.\nOpt-in mutable access to <code>Entry</code> keys.\nOpt-in mutable access to <code>IndexMap</code> keys.\nExisting slot with equivalent key.\nA view into an occupied entry in an <code>IndexMap</code>. It is part …\nOpt-in access to the experimental raw entry API.\nA dynamically-sized slice of key-value pairs in an <code>IndexMap</code>…\nA splicing iterator for <code>IndexMap</code>.\nVacant slot (no equivalent key in the map).\nA view into a vacant entry in an <code>IndexMap</code>. It is part of …\nAn iterator over the values of an <code>IndexMap</code>.\nA mutable iterator over the values of an <code>IndexMap</code>.\nMoves all key-value pairs from <code>other</code> into <code>self</code>, leaving …\nReturns a mutable slice of all the key-value pairs in the …\nReturns a slice of all the key-value pairs in the map.\nSearch over a sorted map with a comparator function.\nSearch over a sorted map with an extraction function.\nSearch over a sorted map for a key.\nReturn the number of elements the map can hold without …\nRemove all key-value pairs in the map, while preserving …\nReturn <code>true</code> if an equivalent to <code>key</code> exists in the map.\nThis is the core implementation that doesn’t depend on …\nReturn an empty <code>IndexMap</code>\nClears the <code>IndexMap</code> in the given index range, returning …\nGet the given key’s corresponding entry in the map for …\nExtend the map with all key-value pairs in the iterable.\nExtend the map with all key-value pairs in the iterable.\nGet the first key-value pair\nGet the first entry in the map for in-place manipulation.\nGet the first key-value pair, with mutable access to the …\nExamples\nReturns the argument unchanged.\nCreate an <code>IndexMap</code> from the sequence of key-value pairs in …\nReturn a reference to the value stored for <code>key</code>, if it is …\nReturn item index, key and value\nReturn item index, mutable reference to key and value\nGet a key-value pair by index\nGet an entry in the map by index for in-place manipulation.\nGet a key-value pair by index\nReturn mutable reference to key and value at an index.\nReturn item index, if it exists in the map\nReturn references to the key-value pair stored for <code>key</code>, if …\nReturns a slice of key-value pairs in the given range of …\nReturns a mutable slice of key-value pairs in the given …\nReturn a reference to the map’s <code>BuildHasher</code>.\nReturns a reference to the value at the supplied <code>index</code>.\nReturns a reference to the value corresponding to the …\nReturns a mutable reference to the value corresponding to …\nReturns a mutable reference to the value at the supplied …\nInsert a key-value pair in the map.\nInsert a key-value pair in the map before the entry at the …\nInsert a key-value pair in the map, and get their index.\nInsert a key-value pair in the map at its ordered position …\nCalls <code>U::from(self)</code>.\nConverts into a boxed slice of all the key-value pairs in …\nReturn an owning iterator over the keys of the map, in …\nReturn an owning iterator over the values of the map, in …\nReturns true if the map contains no elements.\nReturn an iterator over the key-value pairs of the map, in …\nReturn an iterator over the key-value pairs of the map, in …\nReturn an iterator over the key-value pairs of the map, in …\nGets a mutable reference to the entry’s key, either …\nReturn an iterator over the keys of the map, in their order\nGet the last key-value pair\nGet the last entry in the map for in-place manipulation.\nGet the last key-value pair, with mutable access to the …\nReturn the number of key-value pairs in the map.\nMoves the position of a key-value pair from one index to …\nCreate a new map. (Does not allocate.)\nReturns the index of the partition point of a sorted map …\nRemove the last key-value pair\nCreates a raw entry builder for the <code>IndexMap</code>.\nOpt-in access to the experimental raw entry API.\nCreates a raw immutable entry builder for the <code>IndexMap</code>.\nRemove the key-value pair equivalent to <code>key</code> and return its …\nRemove and return the key-value pair equivalent to <code>key</code>.\nReserve capacity for <code>additional</code> more key-value pairs.\nReserve capacity for <code>additional</code> more key-value pairs, …\nScan through each key-value pair in the map and keep those …\nScan through each key-value pair in the map and keep those …\nReverses the order of the map’s key-value pairs in place.\nInsert a key-value pair in the map at the given index.\nRemove the key-value pair equivalent to <code>key</code> and return its …\nRemove and return the key-value pair equivalent to <code>key</code>.\nRemove the key-value pair equivalent to <code>key</code> and return it …\nRemove the key-value pair by index\nShrink the capacity of the map with a lower limit.\nShrink the capacity of the map as much as possible.\nSort the map’s key-value pairs in place using the …\nSort the map’s key-value pairs in place using a sort-key …\nSort the map’s key-value pairs by the default ordering …\nSort the map’s key-value pairs in place using the …\nSort the map’s key-value pairs by the default ordering …\nSort the key-value pairs of the map and return a by-value …\nSort the key-value pairs of the map and return a by-value …\nCreates a splicing iterator that replaces the specified …\nSplits the collection into two at the given index.\nSwaps the position of two key-value pairs in the map.\nRemove the key-value pair equivalent to <code>key</code> and return its …\nRemove and return the key-value pair equivalent to <code>key</code>.\nRemove the key-value pair equivalent to <code>key</code> and return it …\nRemove the key-value pair by index\nShortens the map, keeping the first <code>len</code> elements and …\nTry to reserve capacity for <code>additional</code> more key-value …\nTry to reserve capacity for <code>additional</code> more key-value …\nReturn an iterator over the values of the map, in their …\nReturn an iterator over mutable references to the values …\nCreate a new map with capacity for <code>n</code> key-value pairs. …\nCreate a new map with capacity for <code>n</code> key-value pairs. …\nCreate a new map with <code>hash_builder</code>.\nCore of the map that does not depend on S\nThe maximum capacity before the <code>entries</code> allocation would …\nMutable references to the parts of an <code>IndexMapCore</code>.\nAppend from another map without checking whether items …\nDecrement all indices in the range <code>start..end</code>.\nentries is a dense vec maintaining entry order.\nErase <code>start..end</code> from <code>indices</code>, and shift <code>end..</code> indices …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturn the index in <code>entries</code> where an equivalent key can be …\nIncrement all indices in the range <code>start..end</code>.\nindices mapping from the entry hash to its index.\nInserts many entries into the indices table without …\nInsert a key-value pair in <code>entries</code>, <em>without</em> checking …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nRemove the last key-value pair\nAppend a key-value pair to <code>entries</code>, <em>without</em> checking …\nOpt-in access to the experimental raw entry API.\nSame as <code>insert_full</code>, except it also replaces the key\nReserve capacity for <code>additional</code> more key-value pairs.\nReserve entries capacity, rounded up to match the indices …\nReserve entries capacity, rounded up to match the indices\nReserve capacity for <code>additional</code> more key-value pairs, …\nInsert a key-value pair in <code>entries</code> at a particular index, …\nRemove an entry by shifting all entries that follow it\nRemove an entry by shifting all entries that follow it\nRemove an entry by shifting all entries that follow it\nRemove an entry by shifting all entries that follow it\nShrink the capacity of the map with a lower bound\nFinish removing an entry by swapping it with the last\nRemove an entry by swapping it with the last\nRemove an entry by swapping it with the last\nRemove an entry by swapping it with the last\nTry to reserve capacity for <code>additional</code> more key-value …\nTry to reserve entries capacity, rounded up to match the …\nTry to reserve capacity for <code>additional</code> more key-value …\nEntry for an existing key-value pair in an <code>IndexMap</code> or a …\nA view into an occupied entry in an <code>IndexMap</code> obtained by …\nExisting slot with equivalent key.\nA view into an occupied entry in an <code>IndexMap</code>. It is part …\nVacant slot (no equivalent key in the map).\nA view into a vacant entry in an <code>IndexMap</code>. It is part of …\nModifies the entry if it is occupied.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGets a reference to the entry’s value in the map.\nGets a reference to the entry’s value in the map.\nGets a mutable reference to the entry’s value in the map.\nGets a mutable reference to the entry’s value in the map.\nReturn the index where the key-value pair exists or will …\nReturn the index of the key-value pair\nReturn the index where a key-value pair may be inserted.\nReturn the index of the key-value pair\nSets the value of the entry to <code>value</code>, and returns the entry…\nInserts the entry’s key and the given value into the …\nSets the value of the entry to <code>value</code>, and returns the entry…\nSets the value of the entry (after inserting if vacant), …\nInserts the entry’s key and the given value into the …\nInserts the entry’s key and the given value into the map …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nTakes ownership of the key, leaving the entry vacant.\nConverts into a mutable reference to the entry’s value …\nConverts into a mutable reference to the entry’s value …\nGets a reference to the entry’s key, either within the …\nGets a reference to the entry’s key in the map.\nGets a reference to the key that was used to find the …\nGets a reference to the entry’s key in the map.\nMoves the position of the entry to a new index by shifting …\nMoves the position of the entry to a new index by shifting …\nInserts a default-constructed value in the entry if it is …\nInserts the given default value in the entry if it is …\nInserts the result of the <code>call</code> function in the entry if it …\nInserts the result of the <code>call</code> function with a reference …\nRemove the key, value pair stored in the map for this …\nRemove and return the key, value pair stored in the map …\nInserts the entry’s key and the given value into the map …\nRemove the key, value pair stored in the map for this …\nRemove the key, value pair stored in the map for this …\nRemove and return the key, value pair stored in the map …\nRemove and return the key, value pair stored in the map …\nSwaps the position of entry with another.\nSwaps the position of entry with another.\nRemove the key, value pair stored in the map for this …\nRemove the key, value pair stored in the map for this …\nRemove and return the key, value pair stored in the map …\nRemove and return the key, value pair stored in the map …\nExisting slot with equivalent key.\nOpt-in access to the experimental raw entry API.\nA builder for computing where in an <code>IndexMap</code> a key-value …\nA builder for computing where in an <code>IndexMap</code> a key-value …\nRaw entry for an existing key-value pair or a vacant …\nA raw view into an occupied entry in an <code>IndexMap</code>. It is …\nA view into a vacant raw entry in an <code>IndexMap</code>. It is part …\nVacant slot (no equivalent key in the map).\nModifies the entry if it is occupied.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nAccess an entry by hash.\nAccess an entry by hash.\nAccess an entry by hash, including its index.\nAccess an entry by key.\nAccess an entry by key.\nAccess an entry by a key and its hash.\nAccess an entry by a key and its hash.\nGets a reference to the entry’s value in the map.\nGets a reference to the entry’s key and value in the map.\nGets a reference to the entry’s key and value in the map.\nGets a mutable reference to the entry’s value in the map.\nReturn the index where the key-value pair exists or may be …\nReturn the index of the key-value pair\nReturn the index where a key-value pair may be inserted.\nAccess the index of an entry by hash.\nSets the value of the entry, and returns the entry’s old …\nInserts the given key and value into the map, and returns …\nInserts the given key and value into the map with the …\nSets the key of the entry, and returns the entry’s old …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nConverts into a mutable reference to the entry’s key in …\nConverts into a mutable reference to the entry’s key and …\nConverts into a mutable reference to the entry’s value …\nGets a reference to the entry’s key in the map.\nGets a mutable reference to the entry’s key in the map.\nMoves the position of the entry to a new index by shifting …\nInserts the given default key and value in the entry if it …\nInserts the result of the <code>call</code> function in the entry if it …\nCreates a raw entry builder for the <code>IndexMap</code>.\nCreates a raw immutable entry builder for the <code>IndexMap</code>.\nRemove the key, value pair stored in the map for this …\nRemove and return the key, value pair stored in the map …\nInserts the given key and value into the map at the given …\nInserts the given key and value into the map with the …\nRemove the key, value pair stored in the map for this …\nRemove and return the key, value pair stored in the map …\nSwaps the position of entry with another.\nRemove the key, value pair stored in the map for this …\nRemove and return the key, value pair stored in the map …\nA draining iterator over the entries of an <code>IndexMap</code>.\nAn owning iterator over the entries of an <code>IndexMap</code>.\nAn owning iterator over the keys of an <code>IndexMap</code>.\nAn owning iterator over the values of an <code>IndexMap</code>.\nAn iterator over the entries of an <code>IndexMap</code>.\nA mutable iterator over the entries of an <code>IndexMap</code>.\nA mutable iterator over the entries of an <code>IndexMap</code>.\nAn iterator over the keys of an <code>IndexMap</code>.\nA splicing iterator for <code>IndexMap</code>.\nAn iterator over the values of an <code>IndexMap</code>.\nA mutable iterator over the values of an <code>IndexMap</code>.\nReturns a mutable slice of the remaining entries in the …\nReturns a slice of the remaining entries in the iterator.\nReturns a slice of the remaining entries in the iterator.\nReturns a slice of the remaining entries in the iterator.\nReturns a slice of the remaining entries in the iterator.\nReturns a slice of the remaining entries in the iterator.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns a reference to the key at the supplied <code>index</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturns a mutable slice of the remaining entries in the …\nReturns a mutable slice of the remaining entries in the …\nOpt-in mutable access to <code>Entry</code> keys.\nOpt-in mutable access to <code>IndexMap</code> keys.\nReturn item index, mutable reference to key and value\nReturn mutable reference to key and value at an index.\nReturn an iterator over the key-value pairs of the map, in …\nGets a mutable reference to the entry’s key, either …\nScan through each key-value pair in the map and keep those …\nExisting slot with equivalent key.\nOpt-in access to the experimental raw entry API.\nA builder for computing where in an <code>IndexMap</code> a key-value …\nA builder for computing where in an <code>IndexMap</code> a key-value …\nRaw entry for an existing key-value pair or a vacant …\nA raw view into an occupied entry in an <code>IndexMap</code>. It is …\nA view into a vacant raw entry in an <code>IndexMap</code>. It is part …\nVacant slot (no equivalent key in the map).\nCreates a raw entry builder for the <code>IndexMap</code>.\nCreates a raw immutable entry builder for the <code>IndexMap</code>.\nA dynamically-sized slice of key-value pairs in an <code>IndexMap</code>…\nSearch over a sorted map with a comparator function.\nSearch over a sorted map with an extraction function.\nSearch over a sorted map for a key.\nGet the first key-value pair.\nGet the first key-value pair, with mutable access to the …\nGet a key-value pair by index.\nGet a key-value pair by index, with mutable access to the …\nReturns a slice of key-value pairs in the given range of …\nReturns a mutable slice of key-value pairs in the given …\nReturn an owning iterator over the keys of the map slice.\nReturn an owning iterator over the values of the map slice.\nReturns true if the map slice contains no elements.\nReturn an iterator over the key-value pairs of the map …\nReturn an iterator over the key-value pairs of the map …\nReturn an iterator over the keys of the map slice.\nGet the last key-value pair.\nGet the last key-value pair, with mutable access to the …\nReturn the number of key-value pairs in the map slice.\nReturns an empty slice.\nReturns an empty mutable slice.\nReturns the index of the partition point of a sorted map …\nDivides one slice into two at an index.\nDivides one mutable slice into two at an index.\nReturns the first key-value pair and the rest of the slice,\nReturns the first key-value pair and the rest of the slice,\nReturns the last key-value pair and the rest of the slice, …\nReturns the last key-value pair and the rest of the slice, …\nReturn an iterator over the values of the map slice.\nReturn an iterator over mutable references to the the …\nA lazy iterator producing elements in the difference of …\nA draining iterator over the items of an <code>IndexSet</code>.\nA hash set where the iteration order of the values is …\nA lazy iterator producing elements in the intersection of …\nAn owning iterator over the items of an <code>IndexSet</code>.\nAn iterator over the items of an <code>IndexSet</code>.\nOpt-in mutable access to <code>IndexSet</code> values.\nA dynamically-sized slice of values in an <code>IndexSet</code>.\nA splicing iterator for <code>IndexSet</code>.\nA lazy iterator producing elements in the symmetric …\nA lazy iterator producing elements in the union of <code>IndexSet</code>…\nMoves all values from <code>other</code> into <code>self</code>, leaving <code>other</code> empty.\nReturns a slice of all the values in the set.\nSearch over a sorted set for a value.\nSearch over a sorted set with a comparator function.\nSearch over a sorted set with an extraction function.\nReturns the set intersection, cloned into a new set.\nReturns the set union, cloned into a new set.\nReturns the set symmetric-difference, cloned into a new …\nReturn the number of elements the set can hold without …\nRemove all elements in the set, while preserving its …\nReturn <code>true</code> if an equivalent to <code>value</code> exists in the set.\nReturn an empty <code>IndexSet</code>\nReturn an iterator over the values that are in <code>self</code> but …\nClears the <code>IndexSet</code> in the given index range, returning …\nGet the first value\nExamples\nReturns the argument unchanged.\nReturn a reference to the value stored in the set, if it …\nReturn item index and value\nReturn item index and mutable reference to the value\nGet a value by index\nReturn mutable reference to the value at an index.\nReturn item index, if it exists in the set\nReturns a slice of values in the given range of indices.\nReturn a reference to the set’s <code>BuildHasher</code>.\nReturns a reference to the value at the supplied <code>index</code>.\nInsert the value into the set.\nInsert the value into the set before the value at the …\nInsert the value into the set, and get its index.\nInsert the value into the set at its ordered position …\nReturn an iterator over the values that are in both <code>self</code> …\nCalls <code>U::from(self)</code>.\nConverts into a boxed slice of all the values in the set.\nReturns <code>true</code> if <code>self</code> has no elements in common with <code>other</code>.\nReturns true if the set contains no elements.\nReturns <code>true</code> if all elements of <code>self</code> are contained in <code>other</code>…\nReturns <code>true</code> if all elements of <code>other</code> are contained in <code>self</code>…\nReturn an iterator over the values of the set, in their …\nGet the last value\nReturn the number of elements in the set.\nMoves the position of a value from one index to another by …\nCreate a new set. (Does not allocate.)\nReturns the index of the partition point of a sorted set …\nRemove the last value\nRemove the value from the set, and return <code>true</code> if it was …\nAdds a value to the set, replacing the existing value, if …\nAdds a value to the set, replacing the existing value, if …\nReserve capacity for <code>additional</code> more values.\nReserve capacity for <code>additional</code> more values, without …\nScan through each value in the set and keep those where the\nScan through each value in the set and keep those where the\nReverses the order of the set’s values in place.\nInsert the value into the set at the given index.\nRemove the value from the set, and return <code>true</code> if it was …\nRemove the value from the set return it and the index it …\nRemove the value by index\nRemoves and returns the value in the set, if any, that is …\nShrink the capacity of the set with a lower limit.\nShrink the capacity of the set as much as possible.\nSort the set’s values by their default ordering.\nSort the set’s values in place using the comparison …\nSort the set’s values in place using a key extraction …\nSort the set’s values by their default ordering.\nSort the set’s values in place using the comparison …\nSort the values of the set and return a by-value iterator …\nSort the values of the set and return a by-value iterator …\nCreates a splicing iterator that replaces the specified …\nSplits the collection into two at the given index.\nReturns the set difference, cloned into a new set.\nSwaps the position of two values in the set.\nRemove the value from the set, and return <code>true</code> if it was …\nRemove the value from the set return it and the index it …\nRemove the value by index\nRemoves and returns the value in the set, if any, that is …\nReturn an iterator over the values that are in <code>self</code> or …\nRemoves and returns the value in the set, if any, that is …\nShortens the set, keeping the first <code>len</code> elements and …\nTry to reserve capacity for <code>additional</code> more values.\nTry to reserve capacity for <code>additional</code> more values, …\nReturn an iterator over all values that are in <code>self</code> or …\nCreate a new set with capacity for <code>n</code> elements. (Does not …\nCreate a new set with capacity for <code>n</code> elements. (Does not …\nCreate a new set with <code>hash_builder</code>.\nA lazy iterator producing elements in the difference of …\nA draining iterator over the items of an <code>IndexSet</code>.\nA lazy iterator producing elements in the intersection of …\nAn owning iterator over the items of an <code>IndexSet</code>.\nAn iterator over the items of an <code>IndexSet</code>.\nA splicing iterator for <code>IndexSet</code>.\nA lazy iterator producing elements in the symmetric …\nA lazy iterator producing elements in the union of <code>IndexSet</code>…\nReturns a slice of the remaining entries in the iterator.\nReturns a slice of the remaining entries in the iterator.\nReturns a slice of the remaining entries in the iterator.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nOpt-in mutable access to <code>IndexSet</code> values.\nReturn item index and mutable reference to the value\nReturn mutable reference to the value at an index.\nScan through each value in the set and keep those where the\nA dynamically-sized slice of values in an <code>IndexSet</code>.\nSearch over a sorted set for a value.\nSearch over a sorted set with a comparator function.\nSearch over a sorted set with an extraction function.\nGet the first value.\nGet a value by index.\nReturns a slice of values in the given range of indices.\nReturns true if the set slice contains no elements.\nReturn an iterator over the values of the set slice.\nGet the last value.\nReturn the number of elements in the set slice.\nReturns an empty slice.\nReturns the index of the partition point of a sorted set …\nDivides one slice into two at an index.\nReturns the first value and the rest of the slice, or <code>None</code> …\nReturns the last value and the rest of the slice, or <code>None</code> …")