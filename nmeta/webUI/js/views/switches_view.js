nmeta.SwitchesView = Backbone.View.extend({

    initialize:function () {
        var self = this;
        this.model.on("reset", this.render, this);
        // Instantiate SwitchView on 'add' callback:
        this.model.on("add", function (switch_) {
            self.$el.append(new nmeta.SwitchView({model:switch_}).render().el);
        });
    },

    events: {
        // Refresh button click refreshes collection and renders:
        'click .refresh_switches': function() {
            this.collection.fetch();
            //$('content2').render().el);
            console.log('click .refresh_switches')
            this.render()
        }
    },

    render:function () {
        this.$el.empty();
        // Apply SwitchesView.html template:
        this.$el.html(this.template(this.model.attributes));

        // Iterate through switch views and render them against id="switch"
        _.each(this.model.models, function (switch_) {
            $('#switch', this.el).append(new nmeta.SwitchView({model:switch_}).render().el);
        }, this);
        return this;
    }
});
