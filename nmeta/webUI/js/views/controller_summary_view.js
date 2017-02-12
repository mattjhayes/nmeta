nmeta.ControllerSummaryView = Backbone.View.extend({

    initialize:function () {
        var self = this;
        this.model.on("reset", this.render, this);
    },

    render: function () {
        // Apply ControllerSummaryView.html template:
        this.$el.empty();
        this.$el.html(this.template(this.model.attributes));
        return this;
    }
});
