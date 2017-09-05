//-------- Model for an individual controller Packet-In Chart:
nmeta.ControllerPITimeChartModel = Backbone.Model.extend({
    urlRoot:'/v1/infrastructure/controllers/pi_time',

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
        this.chart_x_labels = [];
        this.ryu_time_data = [];
        this.nmeta_time_data = [];
        var count;
        for(count = 0; count < this.CHART_INTERVALS; count++){
            this.chart_x_labels.push('');
            this.ryu_time_data.push(0);
            this.nmeta_time_data.push(0);
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
        if( this.polling ){
          // Set another polling callback:
          setTimeout(this.executePolling, 1000 * this.intervalSeconds);
        }
        // Add timestamp to labels array:
        this.chart_x_labels.push(this.get("timestamp"));
        if (this.chart_x_labels.length > this.CHART_INTERVALS) {
            this.chart_x_labels.shift();
        }
        // Add values to data arrays:
        this.ryu_time_data.push(this.get("ryu_time_avg"));
        if (this.ryu_time_data.length > this.CHART_INTERVALS) {
            this.ryu_time_data.shift();
        }
        this.nmeta_time_data.push(this.get("pi_time_avg"));
        if (this.nmeta_time_data.length > this.CHART_INTERVALS) {
            this.nmeta_time_data.shift();
        }
    },
});
