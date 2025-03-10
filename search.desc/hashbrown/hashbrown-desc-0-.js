searchState.loadedDescShard("hashbrown", 0, "This crate is a Rust port of Google’s high-performance …\nThe memory allocator returned an error\nError due to the computed capacity exceeding the collection…\nDefault hasher for <code>HashMap</code> and <code>HashSet</code>.\nKey equivalence trait.\nA hash map implemented with quadratic probing and SIMD …\nA hash set implemented as a <code>HashMap</code> where the value is <code>()</code>.\nLow-level hash table with explicit hashing.\nThe error type for <code>try_reserve</code> methods.\nReturns the total amount of memory allocated internally by …\nReturns the total amount of memory allocated internally by …\nReturns the total amount of memory allocated internally by …\nReturns a reference to the underlying allocator.\nReturns a reference to the underlying allocator.\nReturns a reference to the underlying allocator.\nReturns the intersection of <code>self</code> and <code>rhs</code> as a new …\nModifies this set to contain the intersection of <code>self</code> and …\nReturns the union of <code>self</code> and <code>rhs</code> as a new <code>HashSet&lt;T, S&gt;</code>.\nModifies this set to contain the union of <code>self</code> and <code>rhs</code>.\nReturns the symmetric difference of <code>self</code> and <code>rhs</code> as a new …\nModifies this set to contain the symmetric difference of …\nReturns the number of elements the map can hold without …\nReturns the number of elements the set can hold without …\nReturns the number of elements the table can hold without …\nClears the map, removing all key-value pairs. Keeps the …\nClears the set, removing all values.\nClears the table, removing all values.\nReturns <code>true</code> if the set contains a value.\nReturns <code>true</code> if the map contains a value for the specified …\nCreates an empty <code>HashMap&lt;K, V, S, A&gt;</code>, with the <code>Default</code> …\nCreates an empty <code>HashSet&lt;T, S&gt;</code> with the <code>Default</code> value for …\nVisits the values representing the difference, i.e., the …\nClears the map, returning all key-value pairs as an …\nClears the set, returning all elements in an iterator.\nClears the set, returning all elements in an iterator.\nGets the given key’s corresponding entry in the map for …\nGets the given value’s corresponding entry in the set …\nReturns an <code>Entry</code> for an entry in the table with the given …\nGets the given key’s corresponding entry by reference in …\nChecks if this value is equivalent to the given key.\nInserts all new key-values from the iterator to existing …\nInserts all new key-values from the iterator to existing …\nInserts all new key-values from the iterator to existing …\nDrains elements which are true under the given predicate, …\nDrains elements which are true under the given predicate, …\nDrains elements which are true under the given predicate, …\nReturns a reference to an entry in the table with the …\nReturns an <code>OccupiedEntry</code> for an entry in the table with …\nReturns a mutable reference to an entry in the table with …\nExamples\nReturns the argument unchanged.\nReturns the argument unchanged.\nExamples\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns a reference to the value corresponding to the key.\nReturns a reference to the value in the set, if any, that …\nReturns the key-value pair corresponding to the supplied …\nReturns the key-value pair corresponding to the supplied …\nAttempts to get mutable references to <code>N</code> values in the map …\nAttempts to get mutable references to <code>N</code> values in the map …\nAttempts to get mutable references to <code>N</code> values in the map …\nAttempts to get mutable references to <code>N</code> values in the map …\nAttempts to get mutable references to <code>N</code> values in the map …\nAttempts to get mutable references to <code>N</code> values in the map …\nReturns a mutable reference to the value corresponding to …\nInserts the given <code>value</code> into the set if it is not present, …\nInserts a value computed from <code>f</code> into the set if the given …\nA hash map implemented with quadratic probing and SIMD …\nA hash set implemented as a <code>HashMap</code> where the value is <code>()</code>.\nA hash table implemented with quadratic probing and SIMD …\nReturns a reference to the map’s <code>BuildHasher</code>.\nReturns a reference to the set’s <code>BuildHasher</code>.\nReturns a reference to the value corresponding to the …\nInserts a key-value pair into the map.\nAdds a value to the set.\nInserts an element into the <code>HashTable</code> with the given hash …\nInsert a key-value pair into the map without checking if …\nInsert a value the set without checking if the value …\nVisits the values representing the intersection, i.e., the …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCreates an iterator over the entries of a <code>HashMap</code> in …\nCreates an iterator over the entries of a <code>HashMap</code> in …\nCreates a consuming iterator, that is, one that moves each …\nCreates a consuming iterator, that is, one that moves each …\nCreates a consuming iterator visiting all the keys in …\nCreates a consuming iterator visiting all the values in …\nReturns <code>true</code> if <code>self</code> has no elements in common with <code>other</code>. …\nReturns <code>true</code> if the map contains no elements.\nReturns <code>true</code> if the set contains no elements.\nReturns <code>true</code> if the set contains no elements.\nReturns <code>true</code> if the set is a subset of another, i.e., <code>other</code>…\nReturns <code>true</code> if the set is a superset of another, i.e., …\nAn iterator visiting all key-value pairs in arbitrary …\nAn iterator visiting all elements in arbitrary order. The …\nAn iterator visiting all elements in arbitrary order. The …\nAn iterator visiting all elements which may match a hash. …\nA mutable iterator visiting all elements which may match a …\nAn iterator visiting all key-value pairs in arbitrary …\nAn iterator visiting all elements in arbitrary order, with …\nAn iterator visiting all keys in arbitrary order. The …\nReturns the number of elements in the map.\nReturns the number of elements in the set.\nReturns the number of elements in the table.\nCreates an empty <code>HashMap</code>.\nCreates an empty <code>HashSet</code>.\nCreates an empty <code>HashTable</code>.\nCreates an empty <code>HashMap</code> using the given allocator.\nCreates an empty <code>HashSet</code>.\nCreates an empty <code>HashTable</code> using the given allocator.\nRemoves a key from the map, returning the value at the key …\nRemoves a value from the set. Returns whether the value was\nRemoves a key from the map, returning the stored key and …\nAdds a value to the set, replacing the existing value, if …\nReserves capacity for at least <code>additional</code> more elements to …\nReserves capacity for at least <code>additional</code> more elements to …\nReserves capacity for at least <code>additional</code> more elements to …\nRetains only the elements specified by the predicate. …\nRetains only the elements specified by the predicate.\nRetains only the elements specified by the predicate.\nShrinks the capacity of the map with a lower limit. It …\nShrinks the capacity of the set with a lower limit. It …\nShrinks the capacity of the table with a lower limit. It …\nShrinks the capacity of the map as much as possible. It …\nShrinks the capacity of the set as much as possible. It …\nShrinks the capacity of the table as much as possible. It …\nReturns the difference of <code>self</code> and <code>rhs</code> as a new …\nModifies this set to contain the difference of <code>self</code> and <code>rhs</code>…\nVisits the values representing the symmetric difference, …\nRemoves and returns the value in the set, if any, that is …\nTries to insert a key-value pair into the map, and returns …\nTries to reserve capacity for at least <code>additional</code> more …\nTries to reserve capacity for at least <code>additional</code> more …\nTries to reserve capacity for at least <code>additional</code> more …\nVisits the values representing the union, i.e., all the …\nAn iterator visiting all values in arbitrary order. The …\nAn iterator visiting all values mutably in arbitrary order.\nCreates an empty <code>HashMap</code> with the specified capacity.\nCreates an empty <code>HashSet</code> with the specified capacity.\nCreates an empty <code>HashTable</code> with the specified capacity.\nCreates an empty <code>HashMap</code> with the specified capacity, …\nCreates an empty <code>HashSet</code> with the specified capacity, using\nCreates an empty <code>HashMap</code> with the specified capacity, …\nCreates an empty <code>HashSet</code> with the specified capacity, using\nCreates an empty <code>HashMap</code> with the specified capacity using …\nCreates an empty <code>HashSet</code> with the specified capacity.\nCreates an empty <code>HashTable</code> with the specified capacity …\nCreates an empty <code>HashMap</code> which will use the given hash …\nCreates a new empty hash set which will use the given …\nCreates an empty <code>HashMap</code> which will use the given hash …\nCreates a new empty hash set which will use the given …\nThe layout of the allocation request that failed.\nA draining iterator over the entries of a <code>HashMap</code> in …\nA view into a single entry in a map, which may either be …\nA view into a single entry in a map, which may either be …\nA draining iterator over entries of a <code>HashMap</code> which don’…\nA hash map implemented with quadratic probing and SIMD …\nAn owning iterator over the entries of a <code>HashMap</code> in …\nAn owning iterator over the keys of a <code>HashMap</code> in arbitrary …\nAn owning iterator over the values of a <code>HashMap</code> in …\nAn iterator over the entries of a <code>HashMap</code> in arbitrary …\nA mutable iterator over the entries of a <code>HashMap</code> in …\nAn iterator over the keys of a <code>HashMap</code> in arbitrary order. …\nAn occupied entry.\nAn occupied entry.\nA view into an occupied entry in a <code>HashMap</code>. It is part of …\nThe error returned by <code>try_insert</code> when the key already …\nA vacant entry.\nA vacant entry.\nA view into a vacant entry in a <code>HashMap</code>. It is part of the …\nA view into a vacant entry in a <code>HashMap</code>. It is part of the …\nAn iterator over the values of a <code>HashMap</code> in arbitrary …\nA mutable iterator over the values of a <code>HashMap</code> in …\nProvides in-place mutable access to an occupied entry …\nProvides in-place mutable access to an occupied entry …\nProvides shared access to the key and owned access to the …\nThe entry in the map that was already occupied.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGets a reference to the value in the entry.\nGets a mutable reference to the value in the entry.\nSets the value of the entry, and returns an <code>OccupiedEntry</code>.\nSets the value of the entry, and returns the entry’s old …\nSets the value of the entry with the <code>VacantEntry</code>’s key, …\nSets the value of the entry, and returns an <code>OccupiedEntry</code>.\nSets the value of the entry with the <code>VacantEntryRef</code>’s …\nSets the value of the entry with the <code>VacantEntry</code>’s key, …\nSets the value of the entry with the <code>VacantEntryRef</code>’s …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nTake ownership of the key.\nConverts the <code>OccupiedEntry</code> into a mutable reference to the …\nReturns a reference to this entry’s key.\nGets a reference to the key in the entry.\nGets a reference to the key that would be used when …\nReturns a reference to this entry’s key.\nGets a reference to the key that would be used when …\nEnsures a value is in the entry by inserting the default …\nEnsures a value is in the entry by inserting the default …\nEnsures a value is in the entry by inserting the default …\nEnsures a value is in the entry by inserting the default …\nEnsures a value is in the entry by inserting the result of …\nEnsures a value is in the entry by inserting the result of …\nEnsures a value is in the entry by inserting, if empty, …\nEnsures a value is in the entry by inserting, if empty, …\nTakes the value out of the entry, and returns it. Keeps …\nTake the ownership of the key and value from the map. …\nProvides shared access to the key and owned access to the …\nThe value which was not inserted, because the entry was …\nA lazy iterator producing elements in the difference of …\nA draining iterator over the items of a <code>HashSet</code>.\nA view into a single entry in a set, which may either be …\nA draining iterator over entries of a <code>HashSet</code> which don’…\nA hash set implemented as a <code>HashMap</code> where the value is <code>()</code>.\nA lazy iterator producing elements in the intersection of …\nAn owning iterator over the items of a <code>HashSet</code>.\nAn iterator over the items of a <code>HashSet</code>.\nAn occupied entry.\nA view into an occupied entry in a <code>HashSet</code>. It is part of …\nA lazy iterator producing elements in the symmetric …\nA lazy iterator producing elements in the union of <code>HashSet</code>…\nA vacant entry.\nA view into a vacant entry in a <code>HashSet</code>. It is part of the …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns a reference to this entry’s value.\nGets a reference to the value in the entry.\nGets a reference to the value that would be used when …\nSets the value of the entry, and returns an <code>OccupiedEntry</code>.\nSets the value of the entry with the <code>VacantEntry</code>’s value.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nTake ownership of the value.\nEnsures a value is in the entry by inserting if it was …\nTakes the value out of the entry, and returns it. Keeps …\nType representing the absence of an entry, as returned by …\nA draining iterator over the items of a <code>HashTable</code>.\nA view into a single entry in a table, which may either be …\nA draining iterator over entries of a <code>HashTable</code> which don…\nLow-level hash table with explicit hashing.\nAn owning iterator over the entries of a <code>HashTable</code> in …\nAn iterator over the entries of a <code>HashTable</code> in arbitrary …\nAn iterator over the entries of a <code>HashTable</code> that could …\nA mutable iterator over the entries of a <code>HashTable</code> that …\nA mutable iterator over the entries of a <code>HashTable</code> in …\nAn occupied entry.\nA view into an occupied entry in a <code>HashTable</code>. It is part …\nA vacant entry.\nA view into a vacant entry in a <code>HashTable</code>. It is part of …\nProvides in-place mutable access to an occupied entry …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGets a reference to the value in the entry.\nGets a mutable reference to the value in the entry.\nSets the value of the entry, replacing any existing value …\nInserts a new element into the table with the hash that …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nConverts the <code>OccupiedEntry</code> into a mutable reference to the …\nConverts the <code>OccupiedEntry</code> into a mutable reference to the …\nConverts the <code>VacantEntry</code> into a mutable reference to the …\nConverts the <code>AbsentEntry</code> into a mutable reference to the …\nEnsures a value is in the entry by inserting if it was …\nEnsures a value is in the entry by inserting the result of …\nTakes the value out of the entry, and returns it along …")