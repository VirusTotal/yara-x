/*
  Comment
*/

rule test {
    strings:
        $a = "foo"
    condition:
        $a  // Commment
}
