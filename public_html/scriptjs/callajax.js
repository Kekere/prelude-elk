$.ajax({
    type: 'POST',       
    url: "../scriptphp/prelude.php",
    dataType: 'json',
    context: document.body,
    global: false,
    async:false,
    success: function(data) {
        $('#your-hidden-address').val(data["address"]);
        $('#your-hidden-protocol').val(data["protocol"]);
        $('#your-hidden-port').val(data["port"]);
        $('#your-hidden-severity').val(data["severity"]);
	      $('#your-hidden-addresssource').val(data["addresssource"]);
        $('#your-hidden-protocolsource').val(data["protocolsource"]);
        $('#your-hidden-portsource').val(data["portsource"]);
        $('#your-hidden-timestamp').val(data["timestamp"]);
        setInterval('refreshPage()', 150000);
    }
})
function refreshPage() {
  location.reload(true);
}

