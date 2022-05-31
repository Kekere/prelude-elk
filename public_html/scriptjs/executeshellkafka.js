if(localStorage.getItem('sendalert')=='1'){
$.ajax
    ({
        type: "POST",
        dataType : 'json',
        global: false,
        async:false,
        url: './scriptphp/executeproducer.php',
        success: function () {alert("Thanks!"); },
        failure: function() {alert("Error!");}
    });
}