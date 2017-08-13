nmeta.ControllerSummaryView = Backbone.View.extend({

    initialize:function () {
        var self = this;
        this.model.on("reset", this.render, this);
        this.model.on('change', this.render, this);
    },

    events: {
        // Refresh button click refreshes collection and renders:
        'click .refresh_controller_summary': function() {
            this.model.fetch();
            this.render()
        }
    },

    render: function () {
        // Apply ControllerSummaryView.html template:
        this.$el.empty();
        this.$el.html(this.template(this.model.attributes));
        return this;
    }
});
