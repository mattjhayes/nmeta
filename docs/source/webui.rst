######
Web UI
######

The nmeta web UI provides a graphical interface into network metadata.
It is currently under construction, so functionality is limited
and results will vary...

To use the web UI, start nmeta (alias nm), start the nmeta external API
(alias nma) and then point a local (doesn't have to be local) browser at:

`<http://localhost:8081/webUI/index.html>`_

The architecture of the WebUI and REST interface are shown in
the diagram below:

.. image:: images/webui_archtecture.png

The Web Server, Ryu/nmeta and the MongoDB database all run independently.
Backbone.js is the JavaScript framework used to power the UI in the browser.
Bootstrap is the web framework used to style the presentation of the UI.

