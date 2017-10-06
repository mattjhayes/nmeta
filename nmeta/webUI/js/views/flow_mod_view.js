nmeta.FlowModView = Backbone.View.extend({

    // Render flow mod view inside table tr tags:
    tagName:"tr",

    render:function () {
        // Manipulate the response data to suit view:
        // Empty el:
        this.$el.empty();

        // Convert match JSONs to string so they display in HTML:
        var data = this.model.toJSON();
        data.forward_match = JSON.stringify(data.forward_match)
        data.reverse_match = JSON.stringify(data.reverse_match)

        // Reformat string to make multi-line friendly by replacing
        // commas with carriage returns:
        data.forward_match = data.forward_match.replace(/,/g, "\n");
        data.reverse_match = data.reverse_match.replace(/,/g, "\n");

        // Append data model (including REST response) to el:
        this.$el.append(this.template(data));
        return this;
    }

});
