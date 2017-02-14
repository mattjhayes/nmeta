nmeta.FlowsView = Backbone.View.extend({

    initialize:function () {
        var self = this;
        this.model.on("reset", this.render, this);
        // Instantiate FlowView on 'add' callback:
        this.model.on("add", function (flow) {
            self.$el.append(new nmeta.FlowView({model:flow}).render().el);
        });
    },

    events: {
        'click .refresh': function() {
            Backbone.history.loadUrl();
            return false;
        }
    },

    render:function () {
        this.$el.empty();
        // Apply FlowsView.html template:
        this.$el.html(this.template(this.model.attributes));

        // Iterate through flow views and render them against id="flow"
        _.each(this.model.models, function (flow) {
            $('#flow', this.el).append(new nmeta.FlowView({model:flow}).render().el);
        }, this);
        return this;
    }
});
