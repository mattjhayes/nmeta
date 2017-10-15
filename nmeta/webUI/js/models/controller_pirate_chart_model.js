//-------- Model for an individual controller Packet-In Rate Chart:
nmeta.ControllerPIRateChartModel = Backbone.Model.extend({
    urlRoot:'/v1/infrastructure/controllers/pi_rate',

    // Polling for changes
    polling : true,
    intervalSeconds : 5,
    
    // Number of data points to hold for chart series:
    CHART_INTERVALS : 100,

    initialize : function(){
        // Bind our custom functions to this:
        _.bindAll.apply(_, [this].concat(_.functions(this)));
        
        // Initiate and pre-populate arrays to hold data in correct format
        // for ChartJS:
        this.pi_rate_x_labels = [];
        this.pi_rate_data = [];
        var count;
        for(count = 0; count < this.CHART_INTERVALS; count++){
            this.pi_rate_x_labels.push('');
            this.pi_rate_data.push(0);
        }
    },

    // Start polling for new API data:
    startPolling : function(intervalSeconds){
        this.polling = true;
        if( intervalSeconds ){
          this.intervalSeconds = intervalSeconds;
        }
        this.executePolling();
    },

    // Stop polling for new API data:
    stopPolling : function(){
        this.polling = false;
    },

    // Set callback for completion of API fetch to run onFetch function:
    executePolling : function(){
        this.fetch({success : this.onFetch});
    },

    // Runs after API has returned successfully:
    onFetch : function () {
        // Add timestamp to labels array:
        this.pi_rate_x_labels.push(this.get("timestamp"));
        if (this.pi_rate_x_labels.length > this.CHART_INTERVALS) {
            this.pi_rate_x_labels.shift();
        }
        // Add values to data arrays:
        this.pi_rate_data.push(this.get("pi_rate"));
        if (this.pi_rate_data.length > this.CHART_INTERVALS) {
            this.pi_rate_data.shift();
        }
        // Event to trigger render in view:
        this.trigger('event_controller_pirate_data');
        if( this.polling ){
          // Set another polling callback:
          setTimeout(this.executePolling, 1000 * this.intervalSeconds);
        }
    },
});
