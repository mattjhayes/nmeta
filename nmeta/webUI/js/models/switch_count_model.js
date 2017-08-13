//-------- Model for an individual controller summary:
nmeta.SwitchCountModel = Backbone.Model.extend({
    urlRoot:'/v1/infrastructure/switches/stats/connected_switches',

    // Polling for changes:
    polling : false,
    intervalSeconds : 5,

    initialize : function(){
        //_.bindAll(this, _.functions(this));
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
            console.log('switch_count_model setting setTimeout for polling');
            setTimeout(this.executePolling, 1000 * this.intervalSeconds);
        }
    }
});
