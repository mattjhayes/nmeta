//-------- Model for an individual controller Packet-In Chart:
nmeta.ControllerPITimeChartModel = Backbone.Model.extend({
    urlRoot:'/v1/infrastructure/controllers/pi_time',

    // Polling for changes
    polling : true,
    intervalSeconds : 5,

    initialize : function(){
        _.bindAll.apply(_, [this].concat(_.functions(this)));
    },

    startPolling : function(intervalSeconds){
        this.polling = true;
        if( intervalSeconds ){
          this.intervalSeconds = intervalSeconds;
        }
        this.executePolling();
    },

    stopPolling : function(){
        this.polling = false;
    },

    executePolling : function(){
        this.fetch({success : this.onFetch});
    },

    onFetch : function () {
        if( this.polling ){
          setTimeout(this.executePolling, 1000 * this.intervalSeconds);
        }
    }
});
