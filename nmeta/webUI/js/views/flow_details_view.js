nmeta.FlowDetailsView = Backbone.View.extend({

    initialize:function (options) {

        // Bind 'reset' event to run render function on this collection:
        this.model.on("reset", this.render, this);

        // Display a loading indication whenever the Collection is fetching.
        this.model.on("request", function() {
            this.$el.html("Loading...");
        }, this);

        // Automatically re-render whenever the Collection is populated.
        this.model.on("sync", this.render, this);

        // Bind flow detail 'add' event to create new instance of FlowDetailView
        // and render it against id='flow' (table row):
        this.model.on("add", function (flow) {
          console.log('FlowDetailsView add called');
            $('#flow', this.el).append(new nmeta.FlowDetailView({model:flow}).render().el);
        });
    },

    render:function () {
        console.log('FlowDetailsView render function');

        // Start with empty el:
        this.$el.empty();

        // Apply FlowDetailsView.html template:
        this.$el.html(this.template());

        // Render flow detail models:
        var self = this;
        // Iterate through models in collection:
        _.each(this.model.models, function (flow) {
            // Instantiate flow detail view for model:
            var flowDetailView = new nmeta.FlowDetailView({ model : flow });
            // Append rendered flow detail view to el id="flow":
            $('#flow', this.el).append(flowDetailView.render().el);
        });

        return this;
    }

});
