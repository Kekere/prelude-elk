$.ajax({
    type: 'POST',       
    url: "./scriptphp/iterator.php",
    dataType: 'json',
    context: document.body,
    global: false,
    async:false,
    success: function(data) {
        $('#your-hidden-jsonlist').val(data);
    }
})