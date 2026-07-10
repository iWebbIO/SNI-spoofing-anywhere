'use strict';
'require view';
'require form';
'require uci';

return view.extend({
	load: function () {
		return uci.load('sni-spoof');
	},

	render: function () {
		var m, s, o;

		m = new form.Map('sni-spoof', _('SNI Spoofing'),
			_('Local DPI-bypass relay. In Passwall2, point a node at the listen ' +
			  'address/port below. The relay dials your server IP while sending a ' +
			  'fake SNI, so on-path DPI sees an allowed hostname. It touches no ' +
			  'firewall or routing — it just does its own work.'));

		s = m.section(form.NamedSection, 'main', 'sni-spoof', _('Settings'));
		s.anonymous = true;

		o = s.option(form.Flag, 'enabled', _('Enabled'));
		o.rmempty = false;

		o = s.option(form.Value, 'listen_host', _('Listen address'),
			_('Keep 127.0.0.1 so only this router (Passwall2) can reach it.'));
		o.datatype = 'ipaddr';
		o.placeholder = '127.0.0.1';

		o = s.option(form.Value, 'listen_port', _('Listen port'),
			_('Set your Passwall2 node port to this value.'));
		o.datatype = 'port';
		o.placeholder = '40443';

		o = s.option(form.Value, 'connect_ip', _('Server IP'),
			_('The real destination the relay connects to (your proxy server). ' +
			  'Add this IP to Passwall2’s direct/bypass list so it is not re-proxied.'));
		o.datatype = 'ipaddr';

		o = s.option(form.Value, 'connect_port', _('Server port'));
		o.datatype = 'port';
		o.placeholder = '443';

		o = s.option(form.Value, 'fake_sni', _('Fake SNI'),
			_('The allowed hostname DPI will see, e.g. chatgpt.com.'));
		o.placeholder = 'chatgpt.com';

		return m.render();
	}
});
