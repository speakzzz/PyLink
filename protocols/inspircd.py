"""
inspircd.py: InspIRCd 2.0, 3.x, 4.x protocol module for PyLink.
"""

import threading
import time

from pylinkirc import conf
from pylinkirc.classes import *
from pylinkirc.log import log
from pylinkirc.protocols.ts6_common import TS6BaseProtocol

__all__ = ['InspIRCdProtocol']


class InspIRCdProtocol(TS6BaseProtocol):

    S2S_BUFSIZE = 0  # InspIRCd allows infinitely long S2S messages
    SUPPORTED_IRCDS = ['insp20', 'insp3', 'insp4']
    DEFAULT_IRCD = SUPPORTED_IRCDS[1]

    MAX_PROTO_VER = 1206  # anything above this warns (not officially supported)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.protocol_caps |= {'slash-in-nicks', 'slash-in-hosts', 'underscore-in-hosts'}

        # This is only the default value - on InspIRCd 3 it will be negotiated on connect
        self.casemapping = 'rfc1459'

        # Raw commands sent from servers vary from protocol to protocol.
        self.hook_map = {'FJOIN': 'JOIN', 'RSQUIT': 'SQUIT', 'FMODE': 'MODE',
                         'FTOPIC': 'TOPIC', 'OPERTYPE': 'MODE', 'FHOST': 'CHGHOST',
                         'FIDENT': 'CHGIDENT', 'FNAME': 'CHGNAME', 'SVSTOPIC': 'TOPIC',
                         'SAKICK': 'KICK', 'IJOIN': 'JOIN', 'TAGMSG': 'TAGMSG'}

        ircd_target = self.serverdata.get('target_version', self.DEFAULT_IRCD).lower()
        if ircd_target == 'insp20':
            self.proto_ver = 1202
        elif ircd_target == 'insp3':
            self.proto_ver = 1205
        elif ircd_target == 'insp4':
            self.proto_ver = 1206
        else:
            raise ProtocolError("Unsupported target_version %r: supported values include %s" % (ircd_target, self.SUPPORTED_IRCDS))
        
        log.debug('(%s) inspircd: using protocol version %s for target_version %r', self.name, self.proto_ver, ircd_target)

        # Track prefix mode levels on InspIRCd 3+
        self._prefix_levels = {}

        # Track the modules supported by the uplink.
        self._modsupport = set()

        # Track Membership IDs: {(channel, uid): id}
        self._membids = {}
        # Global counter for generating local membership IDs
        self._membid_counter = 1

        # Settable by plugins (e.g. relay) as needed
        self._endburst_delay = 0

    def _init_vars(self):
        super()._init_vars()
        self._membids = {}
        self._membid_counter = 1

    def _get_next_membid(self):
        mid = self._membid_counter
        self._membid_counter += 1
        return str(mid)

    def _store_membid(self, channel, uid, membid):
        self._membids[(channel, uid)] = membid

    def _get_membid(self, channel, uid):
        return self._membids.get((channel, uid))

    def _remove_membid(self, channel, uid):
        if (channel, uid) in self._membids:
            del self._membids[(channel, uid)]

    def _cleanup_user_membids(self, uid):
        to_remove = [k for k in self._membids if k[1] == uid]
        for k in to_remove:
            del self._membids[k]

    ### Outgoing commands

    def spawn_client(self, nick, ident='null', host='null', realhost=None, modes=set(),
            server=None, ip='0.0.0.0', realname=None, ts=None, opertype='IRC Operator',
            manipulatable=False):
        
        server = server or self.sid

        if not self.is_internal_server(server):
            raise ValueError('Server %r is not a PyLink server!' % server)

        uid = self.uidgen[server].next_uid()

        ts = ts or int(time.time())
        realname = realname or conf.conf['pylink']['realname']
        realhost = realhost or host
        raw_modes = self.join_modes(modes)
        u = self.users[uid] = User(self, nick, ts, uid, server, ident=ident, host=host,
                                   realname=realname, realhost=realhost, ip=ip,
                                   manipulatable=manipulatable, opertype=opertype)

        self.apply_modes(uid, modes)
        self.servers[server].users.add(uid)

        if self.proto_ver >= 1206:
            # Protocol 1206 (InspIRCd v4) adds a 'duser' (displayed user) field.
            # Format: UID uuid ts nick realhost host realuser duser ip signon +modes ...
            self._send_with_prefix(server, "UID {uid} {ts} {nick} {realhost} {host} {ident} {ident} {ip}"
                               " {ts} {modes} + :{realname}".format(ts=ts, host=host,
                               nick=nick, ident=ident, uid=uid,
                               modes=raw_modes, ip=ip, realname=realname,
                               realhost=realhost))
        else:
            # Protocol 1205 (InspIRCd v3) and older
            self._send_with_prefix(server, "UID {uid} {ts} {nick} {realhost} {host} {ident} {ip}"
                               " {ts} {modes} + :{realname}".format(ts=ts, host=host,
                               nick=nick, ident=ident, uid=uid,
                               modes=raw_modes, ip=ip, realname=realname,
                               realhost=realhost))

        if ('o', None) in modes or ('+o', None) in modes:
            self._oper_up(uid, opertype)
        return u

    def join(self, client, channel):
        """Joins a PyLink client to a channel."""
        server = self.get_server(client)
        if not self.is_internal_server(server):
            log.error('(%s) Error trying to join %r to %r (no such client exists)', self.name, client, channel)
            raise LookupError('No such PyLink client exists.')

        # Strip out list-modes
        modes = [m for m in self._channels[channel].modes if m[0] not in self.cmodes['*A']]
        
        # Generate Membership ID for InspIRCd 3+
        membid_suffix = ""
        if self.proto_ver >= 1205:
            mid = self._get_next_membid()
            self._store_membid(channel, client, mid)
            membid_suffix = ":" + mid

        self._send_with_prefix(server, "FJOIN {channel} {ts} {modes} :,{uid}{membid}".format(
                ts=self._channels[channel].ts, uid=client, channel=channel,
                modes=self.join_modes(modes), membid=membid_suffix))
        
        self._channels[channel].users.add(client)
        self.users[client].channels.add(channel)

    def sjoin(self, server, channel, users, ts=None, modes=set()):
        """Sends an SJOIN for a group of users to a channel."""
        server = server or self.sid
        assert users, "sjoin: No users sent?"
        log.debug('(%s) sjoin: got %r for users', self.name, users)

        if not server:
            raise LookupError('No such PyLink client exists.')

        modes = modes or self._channels[channel].modes
        orig_ts = self._channels[channel].ts
        ts = ts or orig_ts

        banmodes = []
        regularmodes = []
        for mode in modes:
            modechar = mode[0][-1]
            if modechar in self.cmodes['*A']:
                if (modechar, mode[1]) not in self._channels[channel].modes:
                    banmodes.append(mode)
            else:
                regularmodes.append(mode)

        uids = []
        changedmodes = set(modes)
        namelist = []

        for userpair in users:
            assert len(userpair) == 2, "Incorrect format of userpair: %r" % userpair
            prefixes, user = userpair
            
            # Handle Membership IDs for InspIRCd 3+
            user_str = ','.join(userpair)
            if self.proto_ver >= 1205:
                mid = self._get_next_membid()
                self._store_membid(channel, user, mid)
                user_str += ":" + mid
            
            namelist.append(user_str)
            uids.append(user)
            for m in prefixes:
                changedmodes.add(('+%s' % m, user))
            try:
                self.users[user].channels.add(channel)
            except KeyError:
                log.debug("(%s) sjoin: KeyError trying to add %r to %r's channel list?", self.name, channel, user)

        namelist_str = ' '.join(namelist)
        self._send_with_prefix(server, "FJOIN {channel} {ts} {modes} :{users}".format(
                ts=ts, users=namelist_str, channel=channel,
                modes=self.join_modes(modes)))
        self._channels[channel].users.update(uids)

        if banmodes:
            self._send_with_prefix(server, "FMODE {channel} {ts} {modes} ".format(
                ts=ts, channel=channel, modes=self.join_modes(banmodes)))

        self.updateTS(server, channel, ts, changedmodes)

    def kick(self, source, channel, target, reason=None):
        if not self.is_internal_client(source) and not self.is_internal_server(source):
             raise LookupError('No such PyLink client/server exists.')
        
        # InspIRCd v3/v4 KICK format: KICK <channel> <uid> [membid] :<reason>
        extra_arg = ""
        if self.proto_ver >= 1205:
            mid = self._get_membid(channel, target)
            if mid:
                extra_arg = " " + mid
        
        self._send_with_prefix(source, 'KICK %s %s%s :%s' % (channel, target, extra_arg, reason or source))
        
        self._channels[channel].remove_user(target)
        if target in self.users:
            self.users[target].channels.discard(channel)
        self._remove_membid(channel, target)

    def _oper_up(self, target, opertype=None):
        userobj = self.users[target]
        try:
            otype = opertype or userobj.opertype or 'IRC Operator'
        except AttributeError:
            otype = 'IRC Operator'
        
        if self.remote_proto_ver < 1205:
            otype = otype.replace(" ", "_")
        else:
            otype = ':' + otype

        self._send_with_prefix(target, 'OPERTYPE %s' % otype)

    def mode(self, numeric, target, modes, ts=None):
        if (not self.is_internal_client(numeric)) and \
                (not self.is_internal_server(numeric)):
            raise LookupError('No such PyLink client/server exists.')

        if ('+o', None) in modes and not self.is_channel(target):
            self._oper_up(target)

        self.apply_modes(target, modes)
        joinedmodes = self.join_modes(modes)

        if self.is_channel(target):
            ts = ts or self._channels[target].ts
            self._send_with_prefix(numeric, 'FMODE %s %s %s' % (target, ts, joinedmodes))
        else:
            self._send_with_prefix(numeric, 'MODE %s %s' % (target, joinedmodes))

    def topic(self, source, target, text):
        if not self.is_internal_client(source):
            raise LookupError('No such PyLink client exists.')

        if self.proto_ver >= 1205:
            self._send_with_prefix(source, 'FTOPIC %s %s %s :%s' % (target, self._channels[target].ts, int(time.time()), text))
        else:
            return super().topic(source, target, text)

    def topic_burst(self, source, target, text):
        if not self.is_internal_server(source):
            raise LookupError('No such PyLink server exists.')

        topic_ts = int(time.time())
        servername = self.servers[source].name

        if self.proto_ver >= 1205:
            self._send_with_prefix(source, 'FTOPIC %s %s %s %s :%s' % (target, self._channels[target].ts, topic_ts, servername, text))
        else:
            self._send_with_prefix(source, 'FTOPIC %s %s %s :%s' % (target, topic_ts, servername, text))

        self._channels[target].topic = text
        self._channels[target].topicset = True

    def knock(self, numeric, target, text):
        if not self.is_internal_client(numeric):
            raise LookupError('No such PyLink client exists.')
        self._send_with_prefix(numeric, 'ENCAP * KNOCK %s :%s' % (target, text))

    def update_client(self, target, field, text):
        field = field.upper()

        if field not in ('IDENT', 'HOST', 'REALNAME', 'GECOS'):
            raise NotImplementedError("Changing field %r of a client is "
                                      "unsupported by this protocol." % field)

        if self.is_internal_client(target):
            if field == 'IDENT':
                self.users[target].ident = text
                if self.proto_ver >= 1206:
                    # v4: FIDENT <display> <real>
                    self._send_with_prefix(target, 'FIDENT %s %s' % (text, text))
                else:
                    self._send_with_prefix(target, 'FIDENT %s' % text)
            elif field == 'HOST':
                self.users[target].host = text
                if self.proto_ver >= 1206:
                    # v4: FHOST <display> <real> (keep real host as *)
                    self._send_with_prefix(target, 'FHOST %s *' % text)
                else:
                    self._send_with_prefix(target, 'FHOST %s' % text)
            elif field in ('REALNAME', 'GECOS'):
                self.users[target].realname = text
                self._send_with_prefix(target, 'FNAME :%s' % text)
        else:
            if field == 'IDENT':
                if 'm_chgident.so' not in self._modsupport:
                    raise NotImplementedError('Cannot change idents as m_chgident.so is not loaded')
                self.users[target].ident = text
                self._send_with_prefix(self.sid, 'CHGIDENT %s %s' % (target, text))
                self.call_hooks([self.sid, 'CHGIDENT', {'target': target, 'newident': text}])
            elif field == 'HOST':
                if 'm_chghost.so' not in self._modsupport:
                    raise NotImplementedError('Cannot change hosts as m_chghost.so is not loaded')
                self.users[target].host = text
                self._send_with_prefix(self.sid, 'CHGHOST %s %s' % (target, text))
                self.call_hooks([self.sid, 'CHGHOST', {'target': target, 'newhost': text}])
            elif field in ('REALNAME', 'GECOS'):
                if 'm_chgname.so' not in self._modsupport:
                    raise NotImplementedError('Cannot change real names as m_chgname.so is not loaded')
                self.users[target].realname = text
                self._send_with_prefix(self.sid, 'CHGNAME %s :%s' % (target, text))
                self.call_hooks([self.sid, 'CHGNAME', {'target': target, 'newgecos': text}])

    def oper_notice(self, source, text):
        self._send_with_prefix(self.sid, 'SNONOTICE G :From %s: %s' % (self.get_friendly_name(source), text))

    def numeric(self, source, numeric, target, text):
        if self.proto_ver >= 1205:
            self._send('NUM %s %s %s %s' % (source, target, numeric, text))
        else:
            self._send_with_prefix(self.sid, 'PUSH %s ::%s %s %s %s' % (target, source, numeric, target, text))

    def invite(self, source, target, channel):
        if not self.is_internal_client(source):
            raise LookupError('No such PyLink client exists.')

        if self.proto_ver >= 1205:
            self._send_with_prefix(source, 'INVITE %s %s %d' % (target, channel, self._channels[channel].ts))
        else:
            self._send_with_prefix(source, 'INVITE %s %s' % (target, channel))

    def away(self, source, text):
        if text:
            self._send_with_prefix(source, 'AWAY %s :%s' % (int(time.time()), text))
        else:
            self._send_with_prefix(source, 'AWAY')
        self.users[source].away = text

    def spawn_server(self, name, sid=None, uplink=None, desc=None):
        uplink = uplink or self.sid
        name = name.lower()
        desc = desc or self.serverdata.get('serverdesc') or conf.conf['pylink']['serverdesc']

        if sid is None:
            sid = self.sidgen.next_sid()

        assert len(sid) == 3, "Incorrect SID length"
        if sid in self.servers:
            raise ValueError('A server with SID %r already exists!' % sid)

        for server in self.servers.values():
            if name == server.name:
                raise ValueError('A server named %r already exists!' % name)

        if not self.is_internal_server(uplink):
            raise ValueError('Server %r is not a PyLink server!' % uplink)

        if not self.is_server_name(name):
            raise ValueError('Invalid server name %r' % name)

        self.servers[sid] = Server(self, uplink, name, internal=True, desc=desc)
        if self.proto_ver >= 1205:
            self._send_with_prefix(uplink, 'SERVER %s %s :%s' % (name, sid, desc))
        else:
            self._send_with_prefix(uplink, 'SERVER %s * %s %s :%s' % (name, self.servers[sid].hopcount, sid, desc))

        def endburstf():
            if self._aborted.wait(self._endburst_delay):
                log.debug('(%s) stopping endburstf() for %s as aborted was set', self.name, sid)
                return
            self._send_with_prefix(sid, 'ENDBURST')

        if self._endburst_delay:
            t = threading.Thread(target=endburstf, name="protocols/inspircd delayed ENDBURST thread for %s@%s" % (sid, self.name))
            t.daemon = True
            t.start()
        else:
            self._send_with_prefix(sid, 'ENDBURST')
        return sid

    def set_server_ban(self, source, duration, user='*', host='*', reason='User banned'):
        assert not (user == host == '*'), "Refusing to set ridiculous ban on *@*"
        self._send_with_prefix(source, 'ADDLINE G %s@%s %s %s %s :%s' % (user, host, self.get_friendly_name(source)[:64],
                                                                         int(time.time()), duration, reason))

    ### Core / command handlers

    def _post_disconnect(self):
        super()._post_disconnect()
        log.debug('(%s) _post_disconnect: clearing _modsupport entries. Last: %s', self.name, self._modsupport)
        self._modsupport.clear()
        self._membids.clear()

    def post_connect(self):
        ts = self.start_ts

        f = self.send
        f('CAPAB START %s' % self.proto_ver)
        f('CAPAB CAPABILITIES :PROTOCOL=%s' % self.proto_ver)
        f('CAPAB END')

        host = self.serverdata["hostname"]
        pass_ = self.serverdata["sendpass"]
        sid = self.sid
        sdesc = self.serverdata.get('serverdesc') or conf.conf['pylink']['serverdesc']

        # Protocol 1206 (InspIRCd v4) removed the hopcount parameter from SERVER command
        if self.proto_ver >= 1206:
            f('SERVER {host} {Pass} {sid} :{sdesc}'.format(host=host, Pass=pass_, sid=sid, sdesc=sdesc))
        else:
            # Protocol 1205 (InspIRCd v3) and older include hopcount
            f('SERVER {host} {Pass} 0 {sid} :{sdesc}'.format(host=host, Pass=pass_, sid=sid, sdesc=sdesc))

        self._send_with_prefix(self.sid, 'BURST %s' % ts)

        if self.proto_ver >= 1205:
            verstr = self.version()
            for version_type in {'version', 'rawversion'}:
                self._send_with_prefix(self.sid, 'SINFO %s :%s' % (version_type, verstr.split(' ', 1)[0]))
            self._send_with_prefix(self.sid, 'SINFO fullversion :%s' % verstr)
        else:
            self._send_with_prefix(self.sid, 'VERSION :%s' % self.version())
        self._send_with_prefix(self.sid, 'ENDBURST')

        self.extbans_acting = {'quiet': 'm:', 'ban_nonick': 'N:', 'ban_blockcolor': 'c:',
                               'ban_partmsgs': 'p:', 'ban_invites': 'A:', 'ban_blockcaps': 'B:',
                               'ban_noctcp': 'C:', 'ban_nokicks': 'Q:', 'ban_stripcolor': 'S:',
                               'ban_nonotice': 'T:'}
        self.extbans_matching = {'ban_inchannel': 'j:', 'ban_realname': 'r:', 'ban_server': 's:',
                                 'ban_certfp': 'z:', 'ban_opertype': 'O:', 'ban_account': 'R:',
                                 'ban_unregistered_matching': 'U:'}

    def handle_capab(self, source, command, args):
        if args[0] == 'START':
            self.remote_proto_ver = protocol_version = int(args[1])

            log.debug("(%s) handle_capab: got remote protocol version %s", self.name, protocol_version)
            if protocol_version < self.proto_ver:
                raise ProtocolError("Remote protocol version is too old! "
                                    "At least %s is needed. (got %s)" %
                                    (self.proto_ver, protocol_version))
            elif protocol_version > self.MAX_PROTO_VER:
                log.warning("(%s) PyLink support for InspIRCd > 4.x is experimental, "
                            "and should not be relied upon for anything important.",
                            self.name)
            elif protocol_version >= 1205 > self.proto_ver:
                log.warning("(%s) Remote server is using InspIRCd 3 or newer, but PyLink is configured for older protocol.", self.name)
                log.warning("(%s) You should enable this by setting the 'target_version' option in your "
                            "InspIRCd server block to 'insp3' or 'insp4'.", self.name)

            if self.proto_ver >= 1205:
                self.cmodes = {'*A': '', '*B': '', '*C': '', '*D': ''}
                self.umodes = {'*A': '', '*B': '', '*C': '', '*D': ''}
                self.prefixmodes.clear()

        if args[0] in {'CHANMODES', 'USERMODES'}:
            mydict = self.cmodes if args[0] == 'CHANMODES' else self.umodes

            for modepair in args[-1].split():
                name, char = modepair.rsplit('=', 1)

                if self.proto_ver >= 1205:
                    parts = name.split(':')
                    modetype = parts[0]
                    name = parts[-1]

                    if modetype == 'simple':
                        mydict['*D'] += char
                    elif modetype == 'param-set':
                        mydict['*C'] += char
                    elif modetype == 'param':
                        mydict['*B'] += char
                    elif modetype == 'list':
                        mydict['*A'] += char
                    elif modetype == 'prefix':
                        if args[0] == 'CHANMODES':
                            self._prefix_levels[name] = int(parts[1])
                            self.prefixmodes[char[-1]] = char[0]

                if name.startswith(('c_', 'u_')):
                    name = name[2:]
                if name == 'reginvite':
                    name = 'regonly'
                if name == 'antiredirect':
                    name = 'noforward'
                if name == 'founder':
                    name = 'owner'
                if name in ('repeat', 'kicknorejoin'):
                    name += '_insp'

                mydict[name] = char[-1]

        elif args[0] == 'CAPABILITIES':
            caps = self.parse_isupport(args[-1])
            log.debug("(%s) handle_capab: capabilities list is %s", self.name, caps)

            if 'NICKMAX' in caps:
                self.maxnicklen = int(caps['NICKMAX'])
            if 'CHANMAX' in caps:
                self.maxchanlen = int(caps['CHANMAX'])
            if 'CASEMAPPING' in caps:
                self.casemapping = caps['CASEMAPPING']
                log.debug('(%s) handle_capab: updated casemapping to %s', self.name, self.casemapping)

            if self.proto_ver < 1205:
                if 'CHANMODES' in caps:
                    self.cmodes['*A'], self.cmodes['*B'], self.cmodes['*C'], self.cmodes['*D'] \
                        = caps['CHANMODES'].split(',')
                if 'USERMODES' in caps:
                    self.umodes['*A'], self.umodes['*B'], self.umodes['*C'], self.umodes['*D'] \
                        = caps['USERMODES'].split(',')
                if 'PREFIX' in caps:
                    self.prefixmodes = self.parse_isupport_prefixes(caps['PREFIX'])

        elif args[0] == 'MODSUPPORT':
            modules = args[-1].split()
            for mod in modules:
                if '=' in mod:
                    mod_name = mod.split('=')[0]
                else:
                    mod_name = mod
                
                self._modsupport.add(mod_name)
                
                if self.remote_proto_ver >= 1206 and not mod_name.endswith('.so'):
                    self._modsupport.add(f"m_{mod_name}.so")

    def handle_kick(self, source, command, args):
        # Note: args[2] is membership ID in v3/v4 if present
        if self.proto_ver >= 1205 and len(args) > 3:
            del args[2]

        channel = args[0]
        target = args[1]
        
        self._remove_membid(channel, target)
        return super().handle_kick(source, command, args)

    def handle_ping(self, source, command, args):
        if len(args) >= 2:
            self._send_with_prefix(args[1], 'PONG %s %s' % (args[1], source), queue=False)
        else:
            self._send_with_prefix(args[0], 'PONG %s' % source, queue=False)

    def handle_fjoin(self, servernumeric, command, args):
        channel = args[0]
        chandata = self._channels[channel].deepcopy()
        userlist = args[-1].split()

        modestring = args[2:-1] or args[2]
        parsedmodes = self.parse_modes(channel, modestring)
        namelist = []
        changedmodes = set(parsedmodes)

        for user in userlist:
            modeprefix, user = user.split(',', 1)
            
            membid = None
            if self.proto_ver >= 1205 and ':' in user:
                user, membid = user.split(':', 1)

            if user not in self.users:
                log.debug('(%s) handle_fjoin: tried to introduce user %s not in our user list, ignoring...',
                          self.name, user)
                continue

            namelist.append(user)
            self.users[user].channels.add(channel)
            
            if membid:
                self._store_membid(channel, user, membid)

            changedmodes |= {('+%s' % mode, user) for mode in modeprefix}
            self._channels[channel].users.add(user)

        their_ts = int(''.join(char for char in args[1] if char.isdigit()))
        self.updateTS(servernumeric, channel, their_ts, changedmodes)

        return {'channel': channel, 'users': namelist, 'modes': parsedmodes, 'ts': their_ts,
                'channeldata': chandata}

    def handle_ijoin(self, source, command, args):
        channel = args[0]
        membid = args[1] 
        
        self.users[source].channels.add(channel)
        self._channels[channel].users.add(source)
        self._store_membid(channel, source, membid)

        if len(args) >= 4 and int(args[2]) <= self._channels[channel].ts:
            self.apply_modes(source, {('+%s' % mode, source) for mode in args[3]})

        return {'channel': channel, 'users': [source], 'modes':
                self._channels[channel].modes}

    def handle_uid(self, numeric, command, args):
        if self.proto_ver >= 1206:
            # v4: uid, nickchanged, nick, realhost, dhost, realuser, duser, ip, signon, +modes
            uid, ts, nick, realhost, host, realuser, duser, ip, signon = args[0:9]
            ident = realuser
            # args[9] is modes, args[10] mode params
            mode_args = args[9:]
        else:
            # v3: uid, ts, nick, realhost, host, ident, ip, signon, +modes
            uid, ts, nick, realhost, host, ident, ip, signon = args[0:8]
            mode_args = args[8:]

        ts = int(ts)
        self._check_nick_collision(nick)
        realname = args[-1]
        self.users[uid] = userobj = User(self, nick, ts, uid, numeric, ident, host, realname, realhost, ip)

        parsedmodes = self.parse_modes(uid, mode_args)
        self.apply_modes(uid, parsedmodes)

        self._check_oper_status_change(uid, parsedmodes)
        self.servers[numeric].users.add(uid)
        return {'uid': uid, 'ts': ts, 'nick': nick, 'realhost': realhost, 'host': host, 'ident': ident, 'ip': ip, 'secure': None}

    def handle_server(self, source, command, args):
        if self.uplink is None:
            servername = args[0].lower()
            
            # v3 (1205) sends: SERVER name pass hopcount sid desc (sid at index 3)
            # v4 (1206) sends: SERVER name pass sid desc (sid at index 2)
            if self.remote_proto_ver >= 1206:
                source = args[2] 
            else:
                source = args[3]

            if args[1] != self.serverdata['recvpass']:
                 raise ProtocolError('recvpass from uplink server %s does not match configuration!' % servername)

            sdesc = args[-1]
            self.servers[source] = Server(self, None, servername, desc=sdesc)
            self.uplink = source
            log.debug('(%s) inspircd: found uplink %s', self.name, self.uplink)
            return

        servername = args[0].lower()
        if self.proto_ver >= 1205:
            sid = args[1]
        else:
            sid = args[3]
        sdesc = args[-1]
        self.servers[sid] = Server(self, source, servername, desc=sdesc)

        return {'name': servername, 'sid': sid, 'text': sdesc}

    def handle_fmode(self, numeric, command, args):
        channel = args[0]
        oldobj = self._channels[channel].deepcopy()
        modes = args[2:]
        changedmodes = self.parse_modes(channel, modes)
        self.apply_modes(channel, changedmodes)
        ts = int(args[1])
        return {'target': channel, 'modes': changedmodes, 'ts': ts,
                'channeldata': oldobj}

    def handle_idle(self, source, command, args):
        if self.serverdata.get('force_whois_extensions', True):
            return {'target': args[0], 'parse_as': 'WHOIS'}

        target = args[0]
        start_time = self.start_ts if (conf.conf['pylink'].get('whois_show_startup_time', True) and
                                       self.get_service_bot(target)) else 0
        self._send_with_prefix(target, 'IDLE %s %s 0' % (source, start_time))

    def handle_ftopic(self, source, command, args):
        channel = args[0]

        if self.proto_ver >= 1205 and command == 'FTOPIC':
            ts = args[2]
            if source in self.users:
                setter = source
            else:
                setter = args[3]
        else:
            ts = args[1]
            setter = args[2]
        ts = int(ts)

        topic = args[-1]
        self._channels[channel].topic = topic
        self._channels[channel].topicset = True
        return {'channel': channel, 'setter': setter, 'ts': ts, 'text': topic}

    handle_svstopic = handle_ftopic

    def handle_opertype(self, target, command, args):
        opertype = args[0].replace("_", " ")
        omode = [('+o', None)]
        self.apply_modes(target, omode)
        self.call_hooks([target, 'CLIENT_OPERED', {'text': opertype}])
        return {'target': target, 'modes': omode}

    def handle_fident(self, numeric, command, args):
        self.users[numeric].ident = newident = args[0]
        return {'target': numeric, 'newident': newident}

    def handle_fhost(self, numeric, command, args):
        self.users[numeric].host = newhost = args[0]
        return {'target': numeric, 'newhost': newhost}

    def handle_fname(self, numeric, command, args):
        self.users[numeric].realname = newgecos = args[0]
        return {'target': numeric, 'newgecos': newgecos}

    def handle_endburst(self, numeric, command, args):
        self.servers[numeric].has_eob = True
        if numeric == self.uplink:
            self.connected.set()
        return {}

    def handle_away(self, numeric, command, args):
        try:
            ts = args[0]
            self.users[numeric].away = text = args[1]
            return {'text': text, 'ts': ts}
        except IndexError:
            self.users[numeric].away = ''
            return {'text': ''}

    def handle_rsquit(self, numeric, command, args):
        target = self._get_SID(args[0])
        if self.is_internal_server(target):
            uplink = self.servers[target].uplink
            reason = 'Requested by %s' % self.get_hostmask(numeric)
            self._send_with_prefix(uplink, 'SQUIT %s :%s' % (target, reason))
            return self.handle_squit(numeric, 'SQUIT', [target, reason])
        else:
            log.debug("(%s) Got RSQUIT for '%s', which is either invalid or not "
                      "a server of ours!", self.name, args[0])

    def handle_metadata(self, numeric, command, args):
        target_arg = args[0]

        if target_arg == '*':
            # Generic server/global metadata
            return

        if target_arg == '@':
            # Membership Metadata (New in v4)
            # Args: @ <uid> <channel> <ts> <membid> <key> <value>
            if len(args) < 7:
                return 
            
            uid = args[1]
            channel = args[2]
            key = args[5]
            value = args[6]
            
            # Hook payload for plugins that care about membership metadata
            # We treat this similar to a client hook but include context
            self.call_hooks([uid, 'CLIENT_MEMBERSHIP_METADATA', 
                             {'channel': channel, 'key': key, 'value': value}])
            return

        if self.is_channel(target_arg):
            # Channel Metadata
            channel = target_arg
            key = args[2]
            value = args[3]
            self.call_hooks([channel, 'CHANNEL_METADATA', {'key': key, 'value': value}])
            return

        # User Metadata
        uid = target_arg
        key = args[1]
        value = args[2]

        if key == 'accountname' and uid in self.users:
            self.call_hooks([uid, 'CLIENT_SERVICES_LOGIN', {'text': value}])
        elif key == 'ssl_cert' and uid in self.users:
            self.users[uid].ssl = True
        elif numeric == self.uplink and key == 'modules':
            # Handle modules list
            for module in value.split():
                if module.startswith('-'):
                    log.debug('(%s) Removing module %s', self.name, module[1:])
                    self._modsupport.discard(module[1:])
                elif module.startswith('+'):
                    log.debug('(%s) Adding module %s', self.name, module[1:])
                    self._modsupport.add(module[1:])

    def handle_tagmsg(self, source, command, args):
        """Handles TAGMSG, used for sending tagged-only messages (e.g. typing notifications)."""
        target = args[0]
        # Just pass it through as a hook for plugins to see
        return {'target': target}

    def handle_version(self, numeric, command, args):
        pass

    def handle_sakick(self, source, command, args):
        target = args[1]
        channel = args[0]
        try:
            reason = args[2]
        except IndexError:
            reason = self.get_friendly_name(source)

        if not self.is_internal_client(target):
            log.warning("(%s) Got SAKICK for client that not one of ours: %s", self.name, target)
            return
        else:
            server = self.get_server(target)

        self.kick(server, channel, target, reason)
        return {'channel': channel, 'target': target, 'text': reason}

    def handle_alltime(self, source, command, args):
        timestring = '%s (%s)' % (time.strftime('%Y-%m-%d %H:%M:%S'), int(time.time()))
        self._send_with_prefix(self.sid, 'NOTICE %s :System time is %s on %s' % (source, timestring, self.hostname()))

    def handle_part(self, source, command, args):
        # Clean up membership ID
        channel = args[0]
        self._remove_membid(channel, source)
        return super().handle_part(source, command, args)

    def handle_quit(self, source, command, args):
        # Clean up all membership IDs for this user
        self._cleanup_user_membids(source)
        return super().handle_quit(source, command, args)

    def handle_kill(self, source, command, args):
        # Clean up all membership IDs for this user
        target = args[0]
        self._cleanup_user_membids(target)
        return super().handle_kill(source, command, args)

    def handle_resync(self, source, command, args):
        """Handles RESYNC requests from the remote server."""
        # v3: RESYNC <channel>
        # v4: RESYNC <channel>
        # Just resend the channel burst.
        channel = args[0]
        if channel in self._channels:
            # We are being asked to resync a channel.
            # We should probably burst FJOINs for this channel.
            # Implementation detail: PyLink doesn't fully support being a hub that can resync others,
            # but we can try to send what we have.
            pass 
        return {}

Class = InspIRCdProtocol
