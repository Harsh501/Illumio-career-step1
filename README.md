# Illumio-career-step1

## Tasks at Hand:
  - Defining a constructor that takes the path to a CSV file ( **File containing the rules** ) as an argument.
  - Defining an **interface** with a method ( **accept_packet** ) which would overriden in the class that implements the inteface.
  
## Thought process:
  - An efficient information retrieval structure is required. **Tries** fit in perfectly.
  - What is a Trie ? 
      - It is a search Tree used to store associative array where the keys are usually strings.
      - Diagrammatically:
       - ![Trie Structure](trie.png)
  - Why Trie ? 
    - Worse case time complexity for insertion and retrieval of element O(L) where L is the length of the word.

## Functional Flow :
  - ![Flow diagram](Insert_info_flow.png)
