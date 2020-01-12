# Illumio-career-step1

## Tasks at Hand:
  - Defining a constructor that takes the path to a CSV file ( **File containing the rules** ) as an argument.
  - Defining an **interface** with a method ( **accept_packet** ) which would overriden in the class that implements the inteface.
  
## Thought process:
  - An efficient information retrieval structure is required. **Tries** fit in perfectly.
  - What is a Trie ? 
      - It is a search Tree used to store associative array where the keys are usually strings.
       Diagrammatically:
                          root
                         /     \
                       "1"      "0"   
                       / \      /  \
                     "11" "10" "00" "01"
                     /      \
                   "110"    "101" .. .. 
                   /    \
                 "1101" "1100" .. .. .. ..
