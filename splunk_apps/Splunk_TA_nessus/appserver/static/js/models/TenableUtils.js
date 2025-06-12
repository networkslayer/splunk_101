define(['underscore'],
	function (_) {
	var utilObj = {

	    validateURL: function(url, product)
		    {
		    	if (!url) {
                return _('Field "'+product+' Server URL" should not be empty').t();
	            }
	            else if (!url.match(/^https/))
	            {
	                return _('Only secure URLs are supported for "'+product+'"').t();
	            }
	            else if (!url.match(/^https\:\/\/[\w\-\./%\&\?]+(?::\d{1,5})?$/))
	            {
	                return _('Field "'+product+' Server URL" format is not correct').t();
	            }
		    }
		};
	return utilObj;

});