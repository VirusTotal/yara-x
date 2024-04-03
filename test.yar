    import "pe"

    rule avkill
    {

    strings:

    	$a1 = "taskkill /im"
    	$a2 = "sc config"
    	$a3 = "start= disabled"
    	$a4 = "net stop"
    	$a5 = /foooo{/

    condition:
    	all of them and pe.is_pe == 0
    }
