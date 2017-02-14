nmeta.IdentitiesView = Backbone.View.extend({

    initialize:function () {
        var self = this;
        this.model.on("reset", this.render, this);
        // Instantiate IdentityView on 'add' callback:
        this.model.on("add", function (identity) {
            self.$el.append(new nmeta.IdentityView({model:identity}).render().el);
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
        // Apply IdentitiesView.html template:
        this.$el.html(this.template(this.model.attributes));

        // Iterate through identity views and render them against id="identity" in table:
        _.each(this.model.models, function (identity) {
            $('#identity', this.el).append(new nmeta.IdentityView({model:identity}).render().el);
        }, this);
        return this;
    }
});
