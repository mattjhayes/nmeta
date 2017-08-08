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
        // Apply SwitchCountView.html template:
        this.$el.empty();
        this.$el.html(this.template(this.model.attributes));
        return this;
    }
});
