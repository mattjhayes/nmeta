nmeta.IdentitiesBackGridView = Backbone.View.extend({

    initialize:function (options) {
        // Specify columns that will be displayed in Backgrid:
        var columns = [{
            name: "harvest_type",
            label: "Harvest Type",
            editable: false,
            cell: "string"
          }, {
            name: "host_name",
            label: "Host Name",
            editable: false,
            cell: "string"
          }, {
            name: "service_name",
            label: "Service Name",
            editable: false,
            cell: "string"
          }, {
            name: "mac_address",
            label: "MAC Address",
            editable: false,
            cell: "string"
          }, {
            name: "ip_address",
            label: "IP Address",
            editable: false,
            cell: "string"
          }];

        // Set up a Backgrid grid to use the pageable collection
        this.pageableGrid = new Backgrid.Grid({
          columns: columns,
          collection: this.model
        });

        // Display a loading indication whenever the Collection is fetching.
        this.model.on("request", function() {
            this.$el.html("Loading...");
        }, this);

        this.model.on('reset', this.render, this);
        this.model.on('change', this.render, this);

    },

    render:function () {
        console.log('IdentitiesBackgridView render function');

        // Start with empty el:
        this.$el.empty();

        // Render the grid:
        this.$el.append(this.pageableGrid.render().el)

        return this;
    },

});
