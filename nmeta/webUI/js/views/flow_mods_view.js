nmeta.FlowModsView = Backbone.View.extend({

    initialize:function (options) {

        // Bind 'reset' event to run render function on this collection:
        this.model.on("reset", this.render, this);

        // Display a loading indication whenever the Collection is fetching.
        this.model.on("request", function() {
            this.$el.html("Loading...");
        }, this);

        // Automatically re-render whenever the Collection is populated.
        this.model.on("sync", this.render, this);

        // Bind flow mod 'add' event to create new instance of FlowModView
        // and render it against id='flow_mod' (table row):
        this.model.on("add", function (flow_mod) {
          console.log('FlowModsView add called');
            $('#flow_mod', this.el).append(new nmeta.FlowModView({model:flow_mod}).render().el);
        });
    },

    render:function () {
        console.log('FlowModsView render function');

        // Start with empty el:
        this.$el.empty();

        // Apply FlowModsView.html template:
        this.$el.html(this.template());

        // Render flow mod models:
        var self = this;
        // Iterate through models in collection:
        _.each(this.model.models, function (flow_mod) {
            // Instantiate flow mod view for model:
            var flowModView = new nmeta.FlowModView({ model : flow_mod });
            // Append rendered flow mod view to el id="flow":
            $('#flow_mods', this.el).append(flowModView.render().el);
        });

        return this;
    }

});
