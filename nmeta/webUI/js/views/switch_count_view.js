nmeta.SwitchCountView = Backbone.View.extend({

    initialize:function () {
        var self = this;
        this.model.on("reset", this.render, this);
    },

    events: {
        // Refresh button click refreshes collection and renders:
        'click .refresh_switch_count': function() {
            this.model.fetch();
            this.render()
        }
    },

    render: function () {
        // Empty el:
        this.$el.empty();

        // Work out what colour, descriptor word and hint for switches HTML:
        var data = this.model.toJSON();
        data.switchesColour = this._switchesColour(data.connected_switches);
        data.switchesWord = this._switchesWord(data.connected_switches);
        data.switchesHint = this._switchesHint(data.connected_switches);
        
        // Append data model (including REST response) to el:
        this.$el.append(this.template(data));
        return this;
    },

    _switchesColour: function(connected_switches) {
        // Return HTML label based on REST API connected_switches value:
        if(connected_switches < 1)
            return 'label-danger';
        else
            return 'label-success';
    },

    _switchesWord: function(connected_switches) {
        // Return word based on REST API connected_switches value:
        if(connected_switches == 1)
            return 'switch';
        else
            return 'switches';
    },

    _switchesHint: function(connected_switches) {
        // Return hint if not connected switches:
        if(connected_switches < 1)
            return 'Hint: check switch is powered on and configured to use controller';
        else
            return '';
    }

});
