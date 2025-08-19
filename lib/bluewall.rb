# frozen_string_literal: true
# BlueWall Firewall Auditor (pfSense/OpenSense - Full XML Support)
# Created by :cillia
require 'yaml'
require 'nokogiri'
require 'set'
require 'json'

class BlueWall
  Rule = Struct.new(:id, :action, :interface, :direction, :protocol, :source, :destination, :dport, :comment, :quick, :schedule, :gateway, :state_type, :nat_rule) do
    def to_s
      parts = ["[#{id}] #{action} #{direction} on #{interface}"]
      parts << "proto=#{protocol}" if protocol && protocol != 'any'
      parts << "src=#{source}" if source && source != 'any'
      parts << "dst=#{destination}" if destination && destination != 'any'
      parts << "dport=#{dport}" if dport
      parts << "(Comment: #{comment})" if comment
      parts << "(Quick)" if quick
      parts << "(Schedule: #{schedule})" if schedule
      parts << "(Gateway: #{gateway})" if gateway
      parts << "(State: #{state_type})"
      parts << "(NAT Rule)" if nat_rule
      parts.join(" ")
    end
  end

  AuditResult = Struct.new(:firewall_type, :rules, :strengths, :weaknesses, :score, :details, :simulated_attacks, :framework_assessments) do
    def to_s
      blue_wall_logo = <<~LOGO.chomp
        ██████╗ ██╗     ██╗   ██╗███████╗██╗    ██╗ █████╗ ██╗     ██╗         ███╗███╗
        ██╔══██╗██║     ██║   ██║██╔════╝██║    ██║██╔══██╗██║     ██║         ██╔╝╚██║
        ██████╔╝██║     ██║   ██║█████╗  ██║ █╗ ██║███████║██║     ██║         ██║  ██║
        ██╔══██╗██║     ██║   ██║██╔══╝  ██║███╗██║██╔══██║██║     ██║         ██║  ██║
        ██████╔╝███████╗╚██████╔╝███████╗╚███╔███╔╝██║  ██║███████╗███████╗    ███╗███║
        ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝    ╚══╝╚══╝
                            created by :cillia
      LOGO

      <<~AUDIT_REPORT
        #{blue_wall_logo}
        --- BlueWall Audit Report ---
        Firewall Type: #{firewall_type}
        ---------------------------
        Strengths:
        #{strengths.empty? ? '  None identified.' : strengths.map { |s| "  - #{s}" }.join("\n")}
        Weaknesses:
        #{weaknesses.empty? ? '  None identified.' : weaknesses.map { |w| "  - #{w}" }.join("\n")}
        Overall Security Score (1-10): #{score.round(3)}
        Details: #{details}
        ---------------------------
        Simulated Attack Scenarios:
        #{simulated_attacks.empty? ? '  No scenarios tested or results found.' : simulated_attacks.map { |s| "  - #{s}" }.join("\n")}
      AUDIT_REPORT
    end
  end

  def initialize
    @supported_firewall_types = {
      'PFSENSE_LIKE' => {
        indicators: ['/pfsense/interfaces', '/pfsense/filter/rule'],
        description: 'A pfSense-like XML structure or configuration.'
      },
      'OPENSENSE_LIKE' => {
        indicators: ['/opnsense/interfaces', '/opnsense/filter/rule'],
        description: 'An OpenSense-like XML configuration.'
      }
    }

    @weights = {
      strength_explicit_wan_deny:             2.5,
      strength_restricted_mgmt_access:        4.0,
      strength_restricted_ssh_access:         4.0,
      strength_no_insecure_services_allowed:  2.5,
      strength_granular_lan_outbound:         1.5,
      strength_specific_wan_inbound_rule:     0.3,
      strength_simulated_attack_explicitly_blocked: 1.5,
      strength_simulated_exfiltration_blocked: 1.5,
      strength_simulated_legitimate_allowed:  0.8,
      strength_all_external_attacks_prevented_overall: 2.0,

      weakness_no_explicit_wan_deny:          -1.5,
      weakness_wan_mgmt_from_any:             -15.0,
      weakness_wan_ssh_from_any:              -15.0,
      weakness_overly_permissive_wan:         -20.0,
      weakness_insecure_service_allowed:      -4.0,
      weakness_broad_lan_outbound:            -1.0,
      weakness_simulated_attack_allowed:      -12.0,
      weakness_simulated_attack_implicitly_blocked: -1.0,
      weakness_simulated_exfiltration_allowed: -10.0,
      weakness_simulated_legitimate_blocked:  -3.0,
      weakness_no_rules_found:                -25.0,
      weakness_stateless_rule:                -1.8,
      weakness_nat_insecure_service:          -6.0
    }

    @max_raw_score_contribution = @weights.values.select { |v| v > 0 }.sum
    @min_raw_score_contribution = @weights.values.select { |v| v < 0 }.sum
    @score_range_buffer = 0.5
  end

  def detect_firewall_type_from_xml(xml_doc)
    @supported_firewall_types.each do |type, info|
      if info[:indicators].all? { |xpath| xml_doc.at_xpath(xpath) }
        return type
      end
    end
    'UNKNOWN'
  end

  def extract_interfaces_from_xml(xml_doc)
    interfaces = {}
    xml_doc.xpath('//interfaces/*/ipaddr').each do |ip_node|
      interface_name = ip_node.parent.name
      interfaces[interface_name.to_sym] = {
        ip: ip_node.content || '',
        net: ip_node.parent.at_xpath('subnet')&.content || ''
      }
    end
    interfaces
  end

  def extract_system_ip_from_xml(xml_doc)
    (xml_doc.at_xpath('//system/wan/ipaddr')&.content ||
     xml_doc.at_xpath('//system/general/hostname')&.content || '')
  end

  def extract_aliases_from_xml(xml_doc)
    aliases = {}
    xml_doc.xpath('//aliases/alias').each do |a|
      name = a.at_xpath('name')&.content
      type = a.at_xpath('type')&.content
      address = a.at_xpath('address')&.content || ''
      descr = a.at_xpath('descr')&.content || ''
      next unless name
      aliases[name] = { type: type, address: address.split(/\s+/), description: descr }
    end
    aliases
  end

  def extract_schedules_from_xml(xml_doc)
    schedules = {}
    xml_doc.xpath('//schedules/schedule').each do |s|
      name = s.at_xpath('name')&.content
      descr = s.at_xpath('descr')&.content || ''
      times = s.at_xpath('times')&.content || ''
      weekdays = s.at_xpath('weekdays')&.content || ''
      months = s.at_xpath('months')&.content || ''
      next unless name
      schedules[name] = { descr: descr, times: times, weekdays: weekdays, months: months }
    end
    schedules
  end

  def extract_nat_rules_from_xml(xml_doc, aliases)
    nat_rules = []
    xml_doc.xpath('//nat/rule').each_with_index do |rule_node, index|
      rule_id = rule_node.at_xpath('id')&.content || "nat_rule_#{index + 1}"
      action = 'ALLOW'
      interface = rule_node.at_xpath('interface')&.content || 'any'
      direction = 'in'
      protocol = rule_node.at_xpath('protocol')&.content || 'any'

      source_node = rule_node.at_xpath('source')
      source = resolve_alias(source_node&.at_xpath('address')&.content, aliases) || 'any'

      destination_node = rule_node.at_xpath('destination')
      destination = resolve_alias(destination_node&.at_xpath('address')&.content, aliases) || 'any'

      dport = rule_node.at_xpath('destination/port')&.content&.to_i
      dport = resolve_alias(dport.to_s, aliases).to_i if dport && aliases.key?(dport.to_s)
      comment = rule_node.at_xpath('descr')&.content
      quick = true
      schedule = nil
      gateway = rule_node.at_xpath('gateway')&.content
      state_type = 'keep state'

      nat_rules << Rule.new(rule_id, action, interface, direction, protocol, source, destination, dport, comment, quick, schedule, gateway, state_type, true)
    end
    nat_rules
  end

  def resolve_alias(value, aliases)
    return value unless value && aliases.key?(value)
    aliases[value][:address].first
  end

  def parse_config_from_xml(xml_doc, aliases)
    rules = []
    xml_doc.xpath('//filter/rule').each_with_index do |rule_node, index|
      rule_id = rule_node.at_xpath('id')&.content || rule_node.at_xpath('descr')&.content || "xml_rule_#{index + 1}"
      action = rule_node.at_xpath('type')&.content == 'block' ? 'DENY' : 'ALLOW'
      interface = rule_node.at_xpath('interface')&.content || 'any'
      direction = rule_node.at_xpath('direction')&.content || 'in'
      protocol = rule_node.at_xpath('protocol')&.content || 'any'

      source_node = rule_node.at_xpath('source/network') || rule_node.at_xpath('source/address')
      source = resolve_alias(source_node&.content, aliases) || 'any'
      source = 'any' if rule_node.at_xpath('source/any')

      destination_node = rule_node.at_xpath('destination/network') || rule_node.at_xpath('destination/address')
      destination = resolve_alias(destination_node&.content, aliases) || 'any'
      destination = 'any' if rule_node.at_xpath('destination/any')

      dport = rule_node.at_xpath('destination/port')&.content&.to_i
      dport = resolve_alias(dport.to_s, aliases).to_i if dport && aliases.key?(dport.to_s)
      comment = rule_node.at_xpath('descr')&.content
      quick = rule_node.at_xpath('quick')&.content == 'on'
      schedule = rule_node.at_xpath('sched')&.content
      gateway = rule_node.at_xpath('gateway')&.content
      state_type = rule_node.at_xpath('statetype')&.content || 'keep state'

      rules << Rule.new(rule_id, action, interface, direction, protocol, source, destination, dport, comment, quick, schedule, gateway, state_type, false)
    end
    rules
  end

  def match_ip_or_network(packet_ip_str, rule_ip_or_network_str, interface_ips)
    packet_ip_str = packet_ip_str.to_s
    rule_ip_or_network_str = rule_ip_or_network_str.to_s
    return true if rule_ip_or_network_str == 'any'
    return true if packet_ip_str == rule_ip_or_network_str

    if rule_ip_or_network_str == 'self'
      return true if packet_ip_str == interface_ips[:wan_ip] || packet_ip_str == interface_ips[:lan_ip]
    end

    if rule_ip_or_network_str.include?('/')
      rule_base_ip, rule_cidr_mask = rule_ip_or_network_str.split('/')
      if rule_cidr_mask == '24' && !rule_base_ip.empty?
        packet_octets = packet_ip_str.split('.')
        rule_octets = rule_base_ip.split('.')
        return packet_octets.size >= 3 && rule_octets.size >= 3 && packet_octets[0..2].join('.') == rule_octets[0..2].join('.')
      end
    end

    false
  end

  def simulate_connection_attempt(rules, packet, system_meta)
    interface_ips = {
      wan_ip: system_meta[:interfaces][:wan][:ip],
      lan_ip: system_meta[:interfaces][:lan][:ip]
    }

    rules.each do |rule|
      next unless rule.interface == 'any' || rule.interface == packet[:interface]
      next unless rule.direction == 'any' || rule.direction == packet[:direction]
      next unless rule.protocol == 'any' || rule.protocol == packet[:protocol]
      next unless match_ip_or_network(packet[:src_ip], rule.source, interface_ips)
      next unless match_ip_or_network(packet[:dst_ip], rule.destination, interface_ips)

      if rule.dport && packet[:dst_port]
        next unless rule.dport == packet[:dst_port]
      elsif rule.dport && !packet[:dst_port]
        next
      end

      return rule.action if rule.quick
      return rule.action
    end

    'IMPLICITLY_BLOCKED'
  end

  def calculate_entropy(strings)
    text = strings.join('').downcase
    freq = Hash.new(0)
    text.each_char { |c| freq[c] += 1 }
    total = text.length.to_f
    return 0 if total == 0
    -freq.values.map { |count| (count / total) * Math.log2(count / total) }.sum
  end

  def calculate_defense_depth(rules)
    interface_count = rules.map(&:interface).uniq.size
    action_diversity = rules.map(&:action).uniq.size
    protocol_diversity = rules.map(&:protocol).uniq.size
    port_specificity = rules.count { |r| r.dport && r.dport > 0 } / rules.size.to_f

    score = (interface_count / 5.0) * 1.0 +
            (action_diversity / 2.0) * 1.0 +
            (protocol_diversity / 5.0) * 1.0 +
            port_specificity * 2.0

    [[score, 5.0].min, 0.0].max
  end

  def audit_rules(rules, firewall_type, system_meta, aliases, nat_rules)
    strengths = []
    weaknesses = []
    raw_score = 0.0
    simulated_attacks = []

    system_ip = system_meta[:system_ip].to_s.downcase
    lan_net = system_meta[:interfaces][:lan][:net].to_s.downcase rescue nil
    wan_ip = system_meta[:interfaces][:wan][:ip].to_s.downcase rescue nil

    # --- Explicit WAN Deny ---
    wan_explicit_block_all = rules.any? do |r|
      r.interface == 'wan' && r.direction == 'in' && r.action == 'DENY' &&
        r.protocol == 'any' && r.source == 'any' && r.destination == 'any'
    end

    if wan_explicit_block_all
      strengths << "Explicit 'DENY all' inbound rule on WAN detected, enhancing clarity and reinforcing default deny."
      raw_score += @weights[:strength_explicit_wan_deny]
    else
      weaknesses << "No explicit 'DENY all' inbound rule on WAN. Relying on implicit deny can lead to oversight."
      raw_score += @weights[:weakness_no_explicit_wan_deny]
    end

    broad_lan_outbound_weakness_added = false
    critical_weakness_types_found = Set.new

    rules.each do |rule|
      if rule.action == 'ALLOW' && rule.direction == 'in' &&
         (rule.destination == 'self' || rule.destination == system_ip || rule.destination == wan_ip) &&
         [80, 443].include?(rule.dport)

        if rule.interface == 'wan' && rule.source == 'any'
          weaknesses << "Rule [ID:#{rule.id}] allows firewall management (HTTP/HTTPS) from 'any' source on WAN. **Critical risk!**"
          raw_score += @weights[:weakness_wan_mgmt_from_any]
          critical_weakness_types_found << :wan_mgmt_from_any
        elsif rule.interface == 'wan' && rule.source != 'any'
          strengths << "Rule [ID:#{rule.id}] restricts firewall management access to specific trusted sources on WAN."
          raw_score += @weights[:strength_restricted_mgmt_access]
        end
      end

      if rule.action == 'ALLOW' && rule.direction == 'in' &&
         (rule.destination == 'self' || rule.destination == system_ip || rule.destination == wan_ip) &&
         rule.dport == 22

        if rule.interface == 'wan' && rule.source == 'any'
          weaknesses << "Rule [ID:#{rule.id}] allows SSH access to firewall from 'any' source on WAN. **Critical risk!**"
          raw_score += @weights[:weakness_wan_ssh_from_any]
          critical_weakness_types_found << :wan_ssh_from_any
        elsif rule.interface == 'wan' && rule.source != 'any'
          strengths << "Rule [ID:#{rule.id}] restricts SSH access to firewall to specific trusted sources on WAN."
          raw_score += @weights[:strength_restricted_ssh_access]
        end
      end

      if rule.action == 'ALLOW' && rule.interface == 'wan' && rule.direction == 'in' &&
         (rule.source == 'any' || rule.source.nil?) && (rule.destination == 'any' || rule.destination.nil?) &&
         rule.protocol == 'any'
        weaknesses << "Rule [ID:#{rule.id}] is an overly permissive 'ALLOW' rule from WAN to 'any' destination. **Major vulnerability!**"
        raw_score += @weights[:weakness_overly_permissive_wan]
        critical_weakness_types_found << :overly_permissive_wan
      end

      if rule.action == 'ALLOW' && rule.direction == 'in' && [21, 23, 445, 139].include?(rule.dport)
        weaknesses << "Rule [ID:#{rule.id}] on interface '#{rule.interface}' allows insecure service (port #{rule.dport}). Consider disabling or securing alternatives."
        raw_score += @weights[:weakness_insecure_service_allowed]
        critical_weakness_types_found << :insecure_service_allowed
      end

      if rule.action == 'ALLOW' && rule.interface == 'lan' && rule.direction == 'out' &&
         (rule.source == lan_net || rule.source == 'any') && rule.destination == 'any' && rule.protocol == 'any'
        unless broad_lan_outbound_weakness_added
          weaknesses << "A broad 'ALLOW all' outbound rule from LAN exists. Review to ensure no unnecessary egress traffic."
          raw_score += @weights[:weakness_broad_lan_outbound]
          broad_lan_outbound_weakness_added = true
        end
      end

      if rule.action == 'ALLOW' && rule.interface == 'wan' && rule.direction == 'in' && rule.dport &&
         ![80, 443, 22, 21, 23, 445, 139].include?(rule.dport)
        if rule.source != 'any' && rule.destination != 'any' && rule.protocol != 'any'
          strengths << "Rule [ID:#{rule.id}] provides granular access for a specific service (Port #{rule.dport})."
          raw_score += @weights[:strength_specific_wan_inbound_rule]
        end
      end
    end

    unless broad_lan_outbound_weakness_added
      strengths << "LAN outbound rules appear granular, promoting better control over egress."
      raw_score += @weights[:strength_granular_lan_outbound]
    end

    if rules.empty? && firewall_type != 'UNKNOWN'
      weaknesses << "No firewall rules found in the configuration. This implies an 'allow all' or unknown state."
      raw_score += @weights[:weakness_no_rules_found]
      critical_weakness_types_found << :no_rules_found
    end

    # --- Simulated Attack Scenarios ---
    require 'set'
    simulated_scenarios = [
      { name: "WAN to LAN SSH (Port 22)",
        packet: { src_ip: '203.0.113.1', dst_ip: '10.0.0.100', dst_port: 22, protocol: 'tcp', interface: 'wan', direction: 'in' }, type: :attack, randomize_port: false },
      { name: "WAN to LAN RDP (Port 3389)",
        packet: { src_ip: '203.0.113.1', dst_ip: '10.0.0.100', dst_port: 3389, protocol: 'tcp', interface: 'wan', direction: 'in' }, type: :attack, randomize_port: false },
      { name: "WAN to Firewall HTTP Management (Port 80)",
        packet: { src_ip: '203.0.113.1', dst_ip: system_ip, dst_port: 80, protocol: 'tcp', interface: 'wan', direction: 'in' }, type: :attack, randomize_port: false },
      { name: "WAN to Firewall HTTPS Management (Port 443)",
        packet: { src_ip: '203.0.113.1', dst_ip: system_ip, dst_port: 443, protocol: 'tcp', interface: 'wan', direction: 'in' }, type: :attack, randomize_port: false },
      { name: "WAN to Internal FTP Server (Port 21)",
        packet: { src_ip: '203.0.113.1', dst_ip: '10.0.0.200', dst_port: 21, protocol: 'tcp', interface: 'wan', direction: 'in' }, type: :attack, randomize_port: false },
      { name: "WAN to Internal SMB Share (Port 445)",
        packet: { src_ip: '203.0.113.1', dst_ip: '10.0.0.200', dst_port: 445, protocol: 'tcp', interface: 'wan', direction: 'in' }, type: :attack, randomize_port: false },
      { name: "LAN to External Web (Port 80 - Expected Allowed)",
        packet: { src_ip: '10.0.0.50', dst_ip: '8.8.8.8', dst_port: 80, protocol: 'tcp', interface: 'lan', direction: 'out' }, type: :legitimate, randomize_port: false },
      { name: "WAN to Firewall SSH Brute-force (Random Port)",
        packet: { src_ip: '185.10.10.10', dst_ip: system_ip, protocol: 'tcp', interface: 'wan', direction: 'in' }, type: :attack, randomize_port: true, base_port: 22 },
      { name: "LAN to External Exfiltration (Random High Port)",
        packet: { src_ip: '10.0.0.100', dst_ip: '1.2.3.4', protocol: 'tcp', interface: 'lan', direction: 'out' }, type: :exfiltration, randomize_port: true, port_range: (49152..65535) },
      { name: "DMZ to LAN Database Access (Random Port)",
        packet: { src_ip: '172.16.0.50', dst_ip: '10.0.0.150', protocol: 'tcp', interface: 'dmz', direction: 'in' }, type: :attack, randomize_port: true, base_port: 1433 },
      { name: "WAN to Internal Reverse Shell (Random High Port)",
        packet: { src_ip: '203.0.113.1', dst_ip: '10.0.0.100', protocol: 'tcp', interface: 'wan', direction: 'in' }, type: :attack, randomize_port: true, port_range: (49152..65535) },
      { name: "WAN to Internal Netcat Listener (Random High Port)",
        packet: { src_ip: '203.0.113.1', dst_ip: '10.0.0.100', protocol: 'tcp', interface: 'wan', direction: 'in' }, type: :attack, randomize_port: true, port_range: (49152..65535) },
    ]

    wan_dmz_attacks_prevented_count = 0
    wan_dmz_total_attacks_in_scenarios = 0

    simulated_scenarios.each do |scenario|
      num_loops = scenario[:randomize_port] ? 5 : 1
      scenario_outcomes = []
      scenario_allowed_any_time = false

      num_loops.times do
        current_packet = scenario[:packet].dup
        if scenario[:randomize_port]
          if scenario[:base_port]
            current_packet[:dst_port] = [1, [scenario[:base_port] - 100 + rand(201), 65535].min].max
          elsif scenario[:port_range]
            current_packet[:dst_port] = rand(scenario[:port_range])
          else
            current_packet[:dst_port] = rand(1024..65535)
          end
          scenario_name_with_port = "#{scenario[:name]} (Port #{current_packet[:dst_port]})"
        else
          scenario_name_with_port = scenario[:name]
        end

        outcome = simulate_connection_attempt(rules + nat_rules, current_packet, system_meta)
        scenario_outcomes << "#{scenario_name_with_port}: #{outcome}"
        scenario_allowed_any_time = true if outcome == 'ALLOW'
      end

      simulated_attacks.concat(scenario_outcomes)

      is_external_attack_scenario = (scenario[:name].include?("WAN to") || scenario[:name].include?("DMZ to")) && scenario[:type] == :attack
      is_exfiltration_scenario = scenario[:type] == :exfiltration
      is_legitimate_scenario = scenario[:type] == :legitimate

      if is_external_attack_scenario
        wan_dmz_total_attacks_in_scenarios += 1
      end

      if scenario_allowed_any_time
        if is_legitimate_scenario
          strengths << "Simulated legitimate traffic: '#{scenario[:name]}' was ALLOWED (as expected) in at least one test."
          raw_score += @weights[:strength_simulated_legitimate_allowed]
        elsif is_external_attack_scenario
          weaknesses << "Simulated attack: '#{scenario[:name]}' was ALLOWED in at least one randomized test. **Major exposure!**"
          raw_score += @weights[:weakness_simulated_attack_allowed]
          critical_weakness_types_found << :simulated_attack_allowed
        elsif is_exfiltration_scenario
          weaknesses << "Simulated exfiltration: '#{scenario[:name]}' was ALLOWED in at least one randomized test. Review outbound rules for data leakage prevention."
          raw_score += @weights[:weakness_simulated_exfiltration_allowed]
          critical_weakness_types_found << :simulated_exfiltration_allowed
        end
      else
        if is_legitimate_scenario
          weaknesses << "Simulated legitimate traffic: '#{scenario[:name]}' was BLOCKED/IMPLICITLY_BLOCKED unexpectedly in all tests. This might indicate a functional issue."
          raw_score += @weights[:weakness_simulated_legitimate_blocked]
        elsif is_external_attack_scenario
          if scenario_outcomes.any? { |o| o.include?('DENY') }
            strengths << "Simulated attack: '#{scenario[:name]}' was EXPLICITLY_BLOCKED in tests (strong security)."
            raw_score += @weights[:strength_simulated_attack_explicitly_blocked]
          else
            weaknesses << "Simulated attack: '#{scenario[:name]}' was IMPLICITLY_BLOCKED in all tests. Consider explicit block rules for clarity and robustness."
            raw_score += @weights[:weakness_simulated_attack_implicitly_blocked]
          end
          wan_dmz_attacks_prevented_count += 1
        elsif is_exfiltration_scenario
          if scenario_outcomes.any? { |o| o.include?('DENY') }
            strengths << "Simulated exfiltration: '#{scenario[:name]}' was BLOCKED in tests. Good for data leakage prevention."
            raw_score += @weights[:strength_simulated_exfiltration_blocked]
          else
            weaknesses << "Simulated exfiltration: '#{scenario[:name]}' was IMPLICITLY_BLOCKED. Consider explicit block rules for data leakage prevention."
            raw_score += @weights[:weakness_simulated_exfiltration_allowed]
          end
        end
      end
    end

    if wan_dmz_total_attacks_in_scenarios > 0 && wan_dmz_attacks_prevented_count == wan_dmz_total_attacks_in_scenarios
      strengths << "All simulated external attack attempts were successfully prevented (either explicitly or implicitly blocked)."
      raw_score += @weights[:strength_all_external_attacks_prevented_overall]
    end

    raw_score += (critical_weakness_types_found.size * -5.0)

    effective_min_raw_score = @min_raw_score_contribution - @score_range_buffer
    effective_max_raw_score = @max_raw_score_contribution + @score_range_buffer
    range = effective_max_raw_score - effective_min_raw_score
    normalized_score = range.abs < 1e-9 ? 0.5 : (raw_score - effective_min_raw_score) / range
    final_score = (normalized_score * 9) + 1
    final_score = [1.0, [final_score, 10.0].min].max

    framework_assessments = _assess_frameworks(strengths, weaknesses, final_score)

    { strengths: strengths, weaknesses: weaknesses, score: final_score, simulated_attacks: simulated_attacks, framework_assessments: framework_assessments }
  end

  def _assess_frameworks(strengths, weaknesses, score)
    assessments = {}

    weakness_categories = {
      critical_exposure: weaknesses.any? { |w| w.include?('**Critical risk!**') || w.include?('**Major vulnerability!**') ||
                                            (w.include?('Simulated attack:') && w.include?('ALLOW')) ||
                                            (w.include?('Simulated exfiltration:') && w.include?('ALLOW')) },
      insecure_services: weaknesses.any? { |w| w.include?('insecure service') && w.include?('ALLOW') },
      broad_wan_rules: weaknesses.any? { |w| w.include?('overly permissive') && w.include?('WAN') },
      no_explicit_deny: weaknesses.any? { |w| w.include?('No explicit \'DENY all\' inbound rule on WAN') },
      functional_issues: weaknesses.any? { |w| w.include?('functional issue') },
      no_rules_at_all: weaknesses.any? { |w| w.include?('No firewall rules found in the configuration.') },
      nat_vulnerability: weaknesses.any? { |w| w.include?('NAT Rule') && (w.include?('insecure service') || w.include?('sensitive service')) }
    }

    # --- NIST CSF ---
    nist_score = 5.0
    nist_reasons = []
    nist_reasons << "Overall security score is low (#{sprintf("%.2f", score)}/10)." if score < 6.0
    if weakness_categories[:critical_exposure] || weakness_categories[:nat_vulnerability]
      nist_score -= 2.0
      nist_reasons << "Critical exposures (e.g., exposed management, allowed simulated attacks) detected."
    end
    if weakness_categories[:no_explicit_deny]
      nist_score -= 1.0
      nist_reasons << "Lack of explicit 'DENY all' inbound rule on WAN."
    end
    if weakness_categories[:insecure_services]
      nist_score -= 1.5
      nist_reasons << "Insecure services are allowed."
    end
    if weakness_categories[:functional_issues]
      nist_score -= 0.5
      nist_reasons << "Functional issues detected, potentially impacting system availability."
    end
    nist_score = [1.0, nist_score].max
    nist_status = nist_score >= 3.0 ? 'Pass' : 'Fail'
    assessments['NIST CSF'] = {
      status: nist_status,
      score: nist_score.round(1),
      reason: nist_reasons.empty? ? 'Generally aligns with NIST CSF principles.' : 'Significant weaknesses in core protective controls and risk management.',
      reason_details: nist_reasons
    }

    # --- ISO/IEC 27001 ---
    iso_score = 5.0
    iso_reasons = []
    if weakness_categories[:critical_exposure]
      iso_score -= 2.0
      iso_reasons << "Critical exposures impacting information security objectives."
    end
    if weakness_categories[:insecure_services]
      iso_score -= 1.5
      iso_reasons << "Insecure services are allowed, violating control objectives."
    end
    if weakness_categories[:broad_wan_rules]
      iso_score -= 1.0
      iso_reasons << "Overly broad WAN rules reduce control effectiveness."
    end
    if weakness_categories[:no_rules_at_all]
      iso_score -= 3.0
      iso_reasons << "No firewall rules found, indicating a lack of basic security controls."
    end
    iso_score = [1.0, iso_score].max
    iso_status = iso_score >= 3.0 ? 'Pass' : 'Fail'
    assessments['ISO/IEC 27001'] = {
      status: iso_status,
      score: iso_score.round(1),
      reason: iso_reasons.empty? ? 'Basic technical controls appear to be in place.' : 'Fundamental information security controls are not adequately implemented.',
      reason_details: iso_reasons
    }

    # --- CIS Controls ---
    cis_score = 5.0
    cis_reasons = []
    if weakness_categories[:critical_exposure] || weakness_categories[:nat_vulnerability]
      cis_score -= 2.5
      cis_reasons << "Violations of critical security controls (e.g., exposed management, allowed attacks)."
    end
    if weakness_categories[:insecure_services]
      cis_score -= 1.5
      cis_reasons << "Failure to block insecure services (CIS Control 1)."
    end
    if weakness_categories[:no_explicit_deny]
      cis_score -= 1.0
      cis_reasons << "Lack of explicit deny-all rule (CIS Control 9)."
    end
    if weakness_categories[:broad_wan_rules]
      cis_score -= 1.0
      cis_reasons << "Overly permissive inbound rules (CIS Control 9)."
    end
    cis_score = [1.0, cis_score].max
    cis_status = cis_score >= 3.5 ? 'Pass' : 'Fail'
    assessments['CIS Controls'] = {
      status: cis_status,
      score: cis_score.round(1),
      reason: cis_reasons.empty? ? 'Adheres to many foundational CIS Controls.' : 'Violations of critical security controls identified.',
      reason_details: cis_reasons
    }

    # --- PCI DSS ---
    pci_score = 5.0
    pci_reasons = []
    if weakness_categories[:insecure_services]
      pci_score -= 3.0
      pci_reasons << "Insecure services (e.g., FTP, Telnet, SMB) are allowed, which is a direct PCI DSS violation."
    end
    if weakness_categories[:broad_wan_rules]
      pci_score -= 2.0
      pci_reasons << "Overly permissive WAN rules violate PCI DSS requirement for strict access control."
    end
    if weakness_categories[:critical_exposure] || weakness_categories[:nat_vulnerability]
      pci_score -= 2.0
      pci_reasons << "Critical exposures (e.g., allowed simulated attacks) indicate insufficient segmentation/access controls."
    end
    pci_score = [1.0, pci_score].max
    pci_status = pci_score >= 4.0 ? 'Pass' : 'Fail'
    assessments['PCI DSS'] = {
      status: pci_status,
      score: pci_score.round(1),
      reason: pci_reasons.empty? ? 'No obvious firewall-related PCI DSS violations detected.' : '**Highly likely to fail PCI DSS.** Critical vulnerabilities present.',
      reason_details: pci_reasons
    }

    # --- SOC 2 ---
    soc2_score = 5.0
    soc2_reasons = []
    if weakness_categories[:critical_exposure]
      soc2_score -= 2.0
      soc2_reasons << "Critical exposures impact security and confidentiality criteria."
    end
    if weakness_categories[:broad_wan_rules]
      soc2_score -= 1.0
      soc2_reasons << "Broad WAN rules impact security and processing integrity."
    end
    if weakness_categories[:functional_issues]
      soc2_score -= 0.8
      soc2_reasons << "Functional issues (e.g., blocked legitimate traffic) impact availability."
    end
    if weakness_categories[:insecure_services]
      soc2_score -= 1.2
      soc2_reasons << "Allowing insecure services violates confidentiality and processing integrity."
    end
    soc2_score = [1.0, soc2_score].max
    soc2_status = soc2_score >= 3.5 ? 'Pass' : 'Fail'
    assessments['SOC 2'] = {
      status: soc2_status,
      score: soc2_score.round(1),
      reason: soc2_reasons.empty? ? 'Basic security controls appear adequate.' : 'Significant control deficiencies related to Trust Services Criteria.',
      reason_details: soc2_reasons
    }

    # --- COBIT 2019 ---
    cobit_score = 5.0
    cobit_reasons = []
    if score < 6.0
      cobit_score -= 1.0
      cobit_reasons << "Overall security score is low (#{sprintf("%.2f", score)}/10)."
    end
    if weakness_categories[:no_explicit_deny]
      cobit_score -= 1.0
      cobit_reasons << "Lack of explicit deny policy impacts governance over network access."
    end
    if weakness_categories[:broad_wan_rules]
      cobit_score -= 1.5
      cobit_reasons << "Overly permissive rules indicate poor risk management and control design."
    end
    if weakness_categories[:critical_exposure]
      cobit_score -= 2.0
      cobit_reasons << "Critical exposures reflect failure in MEA (Monitor, Evaluate, and Assess) processes."
    end
    if weakness_categories[:insecure_services]
      cobit_score -= 1.0
      cobit_reasons << "Allowing insecure services violates DSS05 (Managed Security Services)."
    end
    cobit_score = [1.0, cobit_score].max
    cobit_status = cobit_score >= 3.0 ? 'Pass' : 'Fail'
    assessments['COBIT 2019'] = {
      status: cobit_status,
      score: cobit_score.round(1),
      reason: cobit_reasons.empty? ? 'Basic governance of network security is present.' : 'Significant gaps in IT governance and control framework implementation.',
      reason_details: cobit_reasons
    }

    assessments
  end

  def conduct_audit(config_file_path)
    puts "Starting BlueWall audit..."
    unless File.exist?(config_file_path)
      puts "Error: Configuration file not found at '#{config_file_path}'"
      return AuditResult.new('N/A', [], [], ["Configuration file not found: #{config_file_path}"], 1.0, 'Audit failed.', [], {})
    end

    begin
      xml_content = File.read(config_file_path)
      xml_doc = Nokogiri::XML(xml_content) { |c| c.options = Nokogiri::XML::ParseOptions::NOBLANKS }

      system_meta = {
        interfaces: extract_interfaces_from_xml(xml_doc),
        system_ip: extract_system_ip_from_xml(xml_doc)
      }

      firewall_type = detect_firewall_type_from_xml(xml_doc)
      if firewall_type == 'UNKNOWN'
        return AuditResult.new(firewall_type, [], [], ['Unrecognized XML structure.'], 1.0, 'Cannot perform audit.', [], {})
      end

      puts "Detected firewall type: #{firewall_type}"

      aliases = extract_aliases_from_xml(xml_doc)
      schedules = extract_schedules_from_xml(xml_doc)
      nat_rules = extract_nat_rules_from_xml(xml_doc, aliases)
      rules = parse_config_from_xml(xml_doc, aliases)

      puts "Parsed #{rules.count} firewall rules, #{aliases.size} aliases, #{nat_rules.size} NAT rules."

      if rules.empty?
        return AuditResult.new(firewall_type, [], [], ['No firewall rules found.'], 1.0, 'Cannot audit empty ruleset.', [], {})
      end

      audit_findings = audit_rules(rules, firewall_type, system_meta, aliases, nat_rules)
      details = "BlueWall audit completed based on common cybersecurity principles tailored for #{firewall_type} (inspired by CIS Controls and NIST CSF). Score reflects adherence to least privilege, rule specificity, handling of insecure services, and interface-specific security."

      AuditResult.new(
        firewall_type, rules, audit_findings[:strengths], audit_findings[:weaknesses],
        audit_findings[:score], details, audit_findings[:simulated_attacks], audit_findings[:framework_assessments]
      )
    rescue Nokogiri::XML::SyntaxError => e
      puts "Error parsing XML: #{e.message}"
      AuditResult.new('N/A', [], [], ["XML error: #{e.message}"], 1.0, 'Parse failed.', [], {})
    rescue StandardError => e
      puts "Unexpected error: #{e.message}"
      AuditResult.new('ERROR', [], [], ["Unexpected error: #{e.message}"], 1.0, 'Audit failed.', [], {})
    end
  end
end

# --- Main Execution ---
if ARGV.empty?
  puts "Usage: ruby bluewall <config.xml>"
  exit(1)
end

config_file = ARGV[0]
auditor = BlueWall.new
audit_result = auditor.conduct_audit(config_file)

puts audit_result.to_s.split("--- BlueWall Audit Report ---").first

puts "\n---------------------------"
puts "Framework Compliance Assessment (Simplified):"
audit_result.framework_assessments.each do |framework, result|
  status = result[:status] == 'Pass' ? "\e[32mPASS\e[0m" : "\e[31mFAIL\e[0m"
  puts "  - #{framework}: #{status} - #{result[:reason]}"
  
end

print "\nWould you like to see the detailed framework assessment in the console? (yes/no): "
$stdout.flush
user_detail_choice = STDIN.gets.chomp.downcase
if user_detail_choice == 'yes'
  puts "\n" + "="*80
  puts "       DETAILED FRAMEWORK COMPLIANCE ASSESSMENT"
  puts "="*80

  audit_result.framework_assessments.each do |framework, result|
    score = sprintf("%.1f", result[:score])
    status = result[:status]
    status_color = status == 'Pass' ? "\e[32m#{status}\e[0m" : "\e[31m#{status}\e[0m"
    bar_width = 20
    filled = (score.to_f / 5.0 * bar_width).round
    progress_bar = "#" * filled + "-" * (bar_width - filled)
    score_bar = "[#{progress_bar}] #{score}/5.0"

    puts "\n[Framework] #{framework}"
    puts "   Score:    #{score_bar}"
    puts "   Status:   #{status_color}"
    puts "   Summary:  #{result[:reason]}"

    unless result[:reason_details].empty?
      puts "   Breakdown:"
      result[:reason_details].each do |detail|
        # Add plain-text indicators based on content
        indicator = if detail.include?("Critical") || detail.include?("Major")
                      "[CRITICAL]"
                    elsif detail.include?("Lack") || detail.include?("No")
                      "[WARNING]"
                    elsif detail.include?("violates") || detail.include?("exposure")
                      "[FAIL]"
                    elsif detail.include?("Good") || detail.include?("adheres")
                      "[PASS]"
                    else
                      "  -"
                    end
        puts "     #{indicator} #{detail}"
      end
    end

    # Add mitigation advice for failed frameworks
    if status == 'Fail'
      puts "   Recommendations:"
      case framework
      when 'NIST CSF'
        puts "     • Implement explicit deny-all inbound rules on WAN"
        puts "     • Harden management access (SSH/HTTP) from external sources"
        puts "     • Review and block insecure services (e.g., FTP, Telnet)"
      when 'CIS Controls'
        puts "     • Enforce least privilege in firewall rules"
        puts "     • Enable logging and monitoring of rule hits"
        puts "     • Apply 'quick' rules for high-priority blocks"
      when 'PCI DSS'
        puts "     • Disable or restrict access to insecure services (ports 21, 139, 445)"
        puts "     • Implement strict segmentation between cardholder and other zones"
        puts "     • Conduct regular firewall rule reviews"
      when 'SOC 2'
        puts "     • Document firewall change management process"
        puts "     • Ensure availability of legitimate traffic"
        puts "     • Implement automated rule cleanup policies"
      when 'COBIT 2019'
        puts "     • Align firewall policy with governance objectives"
        puts "     • Define ownership and review cycles for rules"
        puts "     • Integrate firewall audits into risk management"
      else
        puts "     • Review rule specificity and default deny posture"
        puts "     • Limit broad ALLOW rules from untrusted interfaces"
      end
    end
  end

  # Summary stats
  total = audit_result.framework_assessments.size
  passed = audit_result.framework_assessments.count { |_, r| r[:status] == 'Pass' }
  failed = total - passed
  compliance_rate = ((passed.to_f / total) * 100).round(1)

  puts "\n" + "-"*50
  puts "Compliance Summary:"
  puts "   Passed:  #{passed} framework#{passed == 1 ? '' : 's'}"
  puts "   Failed:  #{failed} framework#{failed == 1 ? '' : 's'}"
  puts "   Overall Compliance: #{compliance_rate}%"
  puts "-"*50

  # Final advisory
  if failed > 0
    puts "\nACTION REQUIRED: #{failed} framework#{failed == 1 ? ' has' : 's have'} critical gaps. Review recommendations above."
  else
    puts "\nEXCELLENT: All frameworks meet minimum compliance thresholds."
  end
end

  print "
  Would you like to save this report as an HTML file with a score graph? (yes/no): "
  $stdout.flush
  user_html_choice = STDIN.gets.chomp.downcase
  if user_html_choice == 'yes'
    html_filename = "bluewall_report_#{Time.now.strftime('%Y%m%d_%H%M%S')}.html"
    pre_content = audit_result.to_s.split("--- BlueWall Audit Report ---").first.strip
                       .gsub('<', '<').gsub('>', '>').gsub('&', '&amp;').gsub('`', '\\`')
    total_strengths = audit_result.strengths.count
    total_weaknesses = audit_result.weaknesses.count
    total_sim_blocked = audit_result.simulated_attacks.count { |a| !a.include?('ALLOW') }
    total_sim_allowed = audit_result.simulated_attacks.count { |a| a.include?('ALLOW') }
    framework_data = audit_result.framework_assessments.map do |name, result|
      {
        name: name,
        score: result[:score].to_f,
        status: result[:status],
        reason: result[:reason].gsub(/'/, "\\'"),
        details: result[:reason_details].map { |d| d.gsub(/'/, "\\'") }
      }
    end
    defense_depth = auditor.calculate_defense_depth(audit_result.rules)
    entropy_score = auditor.calculate_entropy(audit_result.rules.map(&:to_s))
  html_content = <<~HTML
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
      <title>BlueWall Firewall Audit Report</title>
      <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
      <style id="light-theme">
        :root {
          --bg: #f9fafa;
          --text: #333;
          --card-bg: #fff;
          --header-bg: #1a3b5d;
          --accent: #3498db;
          --pass: #27ae60;
          --fail: #e74c3c;
          --warn: #f39c12;
          --border: #ddd;
          --pre-bg: #1e1e1e;
          --pre-color: #00ff00;
        }
        body {
          font-family: 'Segoe UI', sans-serif;
          background-color: var(--bg);
          color: var(--text);
          margin: 0;
          padding: 0;
          line-height: 1.6;
          transition: background-color 0.3s, color 0.3s;
        }
        header {
          background: var(--header-bg);
          color: white;
          text-align: center;
          padding: 20px;
          border-bottom: 5px solid var(--accent);
        }
        .main-content {
          max-width: 1200px;
          margin: 20px auto;
          padding: 20px;
          background: var(--card-bg);
          border-radius: 10px;
          box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        .tabs {
          display: flex;
          margin-bottom: 20px;
          border-bottom: 1px solid var(--border);
        }
        .tab-button {
          padding: 10px 20px;
          cursor: pointer;
          background: #eee;
          border: 1px solid var(--border);
          border-bottom: none;
          border-radius: 5px 5px 0 0;
          margin-right: 5px;
          font-weight: 600;
        }
        .tab-button.active {
          background: var(--accent);
          color: white;
        }
        .tab-content {
          display: none;
          padding: 20px;
          border: 1px solid var(--border);
          border-radius: 5px;
          background: #fafafa;
        }
        .tab-content.active {
          display: block;
        }
        .chart-wrapper {
          width: 100%;
          height: 300px;
          position: relative;
          margin: 10px 0;
        }
        .chart-wrapper canvas {
          width: 100% !important;
          height: 100% !important;
        }
        .summary-box {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
          gap: 15px;
          margin: 20px 0;
        }
        .box {
          padding: 15px;
          border-radius: 8px;
          color: white;
          font-weight: bold;
          text-align: center;
        }
        .box.score { background: var(--accent); }
        .box.pass { background: var(--pass); }
        .box.fail { background: var(--fail); }
        .box.warn { background: var(--warn); }
        ul {
          padding-left: 15px;
        }
        li {
          margin: 5px 0;
        }
        pre {
          background: var(--pre-bg);
          color: var(--pre-color);
          padding: 15px;
          border-radius: 8px;
          overflow-x: auto;
          font-family: 'Courier New', monospace;
          white-space: pre;
        }
        footer {
          text-align: center;
          margin-top: 30px;
          color: #7f8c8d;
          font-size: 0.9em;
        }
        .theme-toggle {
          position: fixed;
          top: 20px;
          right: 20px;
          background: var(--accent);
          color: white;
          border: none;
          padding: 10px 15px;
          border-radius: 5px;
          cursor: pointer;
          font-weight: bold;
          z-index: 100;
        }
        .critical-risk {
          background: #fef6f6;
          border: 1px solid #e74c3c;
          border-radius: 8px;
          padding: 15px;
          margin: 20px 0;
        }
        .critical-risk h3 {
          color: #e74c3c;
          margin-top: 0;
        }
        .metrics-table {
          width: 100%;
          border-collapse: collapse;
          font-size: 0.9em;
          margin: 20px 0;
        }
        .metrics-table td {
          padding: 8px;
          border-bottom: 1px solid #ddd;
        }
      </style>
      <style id="dark-theme" disabled>
        :root {
          --bg: #121212;
          --text: #e0e0e0;
          --card-bg: #1e1e1e;
          --header-bg: #0d47a1;
          --accent: #1976d2;
          --pass: #4caf50;
          --fail: #f44336;
          --warn: #ff9800;
          --border: #444;
          --pre-bg: #000;
          --pre-color: #00ff00;
        }
        body {
          background-color: var(--bg);
          color: var(--text);
        }
        .tab-button {
          background: #333;
          color: white;
          border-color: var(--border);
        }
        .tab-button.active {
          background: var(--accent);
        }
        .tab-content {
          background: #2a2a2a;
          border-color: var(--border);
        }
        pre {
          background: var(--pre-bg);
          color: var(--pre-color);
        }
        .critical-risk {
          background: #380909;
          border-color: #c62828;
        }
        .critical-risk h3 {
          color: #e57373;
        }
        .metrics-table td {
          border-bottom: 1px solid #555;
        }
      </style>
    </head>
    <body>
      <button class="theme-toggle" onclick="toggleDarkMode()">🌙 Dark Mode</button>
      <header>
        <h1>🔐 BlueWall Firewall Audit Report</h1>
        <p>Generated on #{Time.now.strftime('%Y-%m-%d at %H:%M:%S')}</p>
      </header>
      <div class="main-content">
        <pre id="ascii-art"></pre>
        <div class="summary-box">
          <div class="box score">
            Overall Score<br><strong>#{sprintf("%.2f", audit_result.score)}/10</strong>
          </div>
          <div class="box pass">
            Strengths<br><strong>#{total_strengths}</strong>
          </div>
          <div class="box fail">
            Weaknesses<br><strong>#{total_weaknesses}</strong>
          </div>
          <div class="box warn">
            Type<br><strong>#{audit_result.firewall_type}</strong>
          </div>
        </div>
        <div class="tabs">
          <div class="tab-button active" onclick="openTab(event, 'overview')">📊 Overview</div>
          <div class="tab-button" onclick="openTab(event, 'frameworks')">🎯 Frameworks</div>
          <div class="tab-button" onclick="openTab(event, 'findings')">🔍 Findings</div>
          <div class="tab-button" onclick="openTab(event, 'simulations')">🧪 Simulations</div>
        </div>
        <div id="overview" class="tab-content active">
          <h2>Security Overview</h2>
          <div class="critical-risk" id="critical-risk-container" style="display: none;">
            <h3>🚨 Critical Risks</h3>
            <ul id="critical-risk-list"></ul>
          </div>
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 25px; margin: 20px 0;">
            <div class="chart-wrapper"><canvas id="overallScoreChart"></canvas></div>
            <div class="chart-wrapper"><canvas id="findingsChart"></canvas></div>
            <div class="chart-wrapper"><canvas id="interfaceDistributionChart"></canvas></div>
            <div class="chart-wrapper"><canvas id="actionDistributionChart"></canvas></div>
            <div class="chart-wrapper"><canvas id="protocolDistributionChart"></canvas></div>
            <div class="chart-wrapper"><canvas id="topPortsChart"></canvas></div>
          </div>
          <div style="margin: 30px 0; padding: 20px; background: #f8f9fa; border-radius: 8px;">
            <h3>🔍 Advanced Security Metrics</h3>
            <table class="metrics-table">
              <tr><td><strong>Defense Depth Score</strong></td><td>#{sprintf("%.2f", defense_depth)}/5.0</td></tr>
              <tr><td><strong>Rule Entropy (Complexity)</strong></td><td>#{sprintf("%.2f", entropy_score)}/3.0</td></tr>
              <tr><td><strong>Scheduled Rules</strong></td><td>#{audit_result.rules.count { |r| r.schedule }} rules use time-based access control</td></tr>
              <tr><td><strong>Stateless Rules</strong></td><td>#{audit_result.rules.count { |r| r.state_type != 'keep state' }}</td></tr>
              <tr><td><strong>Quick Rules</strong></td><td>#{audit_result.rules.count { |r| r.quick }} rules use 'quick' evaluation</td></tr>
            </table>
          </div>
        </div>
        <div id="frameworks" class="tab-content">
          <h2>Framework Compliance Assessment</h2>
          <p>Each chart shows compliance score (out of 5).</p>
          <div id="frameworkCharts" style="display: flex; flex-wrap: wrap; justify-content: center; gap: 20px;">
            #{framework_data.map do |data|
              chart_id = data[:name].gsub(/\W+/, '_')
              status_class = data[:status] == 'Pass' ? 'pass' : 'fail'
              <<~HTML
                <div style="text-align:center; width: 30%;">
                  <h3>#{data[:name]}</h3>
                  <div class="chart-wrapper">
                    <canvas id="#{chart_id}_chart"></canvas>
                  </div>
                  <p><strong>Status:</strong> <span class="#{status_class}">#{data[:status]}</span> (#{sprintf("%.1f", data[:score])}/5)</p>
                  <p style="font-size:0.9em; color:#555;"><em>#{data[:reason]}</em></p>
                  <details style="margin-top:10px; font-size:0.85em;">
                    <summary>Why this score?</summary>
                    <ul>
                      #{data[:details].map { |d| "<li>#{d}</li>" }.join('')}
                    </ul>
                  </details>
                </div>
              HTML
            end.join("\n")}
          </div>
        </div>
        <div id="findings" class="tab-content">
          <h2>Strengths & Weaknesses</h2>
          <h3>✅ Strengths</h3>
          <ul>#{audit_result.strengths.map { |s| "<li>#{s}</li>" }.join('')}</ul>
          <h3>❌ Weaknesses</h3>
          <ul>#{audit_result.weaknesses.map { |w| "<li>#{w}</li>" }.join('')}</ul>
        </div>
        <div id="simulations" class="tab-content">
          <h2>Attack Simulation Results</h2>
          <div class="chart-wrapper"><canvas id="simulationsChart"></canvas></div>
          <ul>#{audit_result.simulated_attacks.map { |s| "<li>#{s}</li>" }.join('')}</ul>
        </div>
        <footer>
          Report generated by <strong>BlueWall</strong> — created by :cillia
        </footer>
      </div>
      <script>
        function toggleDarkMode() {
          const darkTheme = document.getElementById('dark-theme');
          const button = document.querySelector('.theme-toggle');
          if (darkTheme.disabled) {
            darkTheme.disabled = false;
            button.textContent = '☀️ Light Mode';
            localStorage.setItem('darkMode', 'enabled');
          } else {
            darkTheme.disabled = true;
            button.textContent = '🌙 Dark Mode';
            localStorage.setItem('darkMode', 'disabled');
          }
        }

        window.addEventListener('DOMContentLoaded', () => {
          if (localStorage.getItem('darkMode') === 'enabled') {
            document.getElementById('dark-theme').disabled = false;
            document.querySelector('.theme-toggle').textContent = '☀️ Light Mode';
          }

          const criticalRisks = #{JSON.generate(audit_result.weaknesses.select { |w| w.include?('**Critical risk!**') })};
          const container = document.getElementById('critical-risk-container');
          const list = document.getElementById('critical-risk-list');
          if (criticalRisks.length > 0) {
            container.style.display = 'block';
            criticalRisks.forEach(risk => {
              const li = document.createElement('li');
              li.innerHTML = '<strong>' + risk.replace(/\*\*/g, '') + '</strong>';
              list.appendChild(li);
            });
          }
        });

        function openTab(evt, tabName) {
          document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
          document.querySelectorAll('.tab-button').forEach(t => t.classList.remove('active'));
          document.getElementById(tabName).classList.add('active');
          evt.currentTarget.classList.add('active');
        }

        document.addEventListener('DOMContentLoaded', function () {
          document.getElementById('ascii-art').textContent = `#{pre_content}`;

          // 1. Overall Score
          new Chart(document.getElementById('overallScoreChart'), {
            type: 'bar',
            data: {
              labels: ['Security Score'],
              datasets: [{
                label: 'Score (1-10)',
                data: [#{audit_result.score}],
                backgroundColor: #{audit_result.score} >= 8 ? '#27ae60' : #{audit_result.score} >= 5 ? '#f39c12' : '#e74c3c',
                borderColor: '#2c3e50',
                borderWidth: 2
              }]
            },
            options: {
              responsive: true,
              maintainAspectRatio: false,
              indexAxis: 'y',
              scales: { x: { min: 0, max: 10 } },
              plugins: { legend: { display: false } }
            }
          });

          // 2. Findings
          new Chart(document.getElementById('findingsChart'), {
            type: 'bar',
            data: {
              labels: ['Findings'],
              datasets: [
                { label: 'Strengths', data: [#{total_strengths}], backgroundColor: '#27ae60', stack: 'stack0' },
                { label: 'Weaknesses', data: [#{total_weaknesses}], backgroundColor: '#e74c3c', stack: 'stack0' }
              ]
            },
            options: {
              responsive: true,
              maintainAspectRatio: false,
              scales: { x: { stacked: true }, y: { stacked: true, beginAtZero: true } },
              plugins: { legend: { position: 'top' } }
            }
          });

          // 3. Interface Distribution
          const interfaceData = #{JSON.generate(audit_result.rules.group_by(&:interface).map { |k, v| [k.to_s, v.size] }.to_h)};
          new Chart(document.getElementById('interfaceDistributionChart'), {
            type: 'pie',
            data: {
              labels: Object.keys(interfaceData),
              datasets: [{
                data: Object.values(interfaceData),
                backgroundColor: ['#3498db', '#e74c3c', '#f39c12', '#9b59b6', '#1abc9c']
              }]
            },
            options: {
              responsive: true,
              maintainAspectRatio: false,
              plugins: { legend: { position: 'bottom' } }
            }
          });

          // 4. Action Distribution
          const actionData = {
            ALLOW: #{audit_result.rules.count { |r| r.action == 'ALLOW' }},
            DENY: #{audit_result.rules.count { |r| r.action == 'DENY' }}
          };
          new Chart(document.getElementById('actionDistributionChart'), {
            type: 'bar',
            data: {
              labels: ['Actions'],
              datasets: [
                { label: 'ALLOW', data: [actionData.ALLOW], backgroundColor: '#27ae60' },
                { label: 'DENY', data: [actionData.DENY], backgroundColor: '#e74c3c' }
              ]
            },
            options: {
              responsive: true,
              maintainAspectRatio: false,
              scales: { x: { stacked: true }, y: { stacked: true, beginAtZero: true } },
              plugins: { legend: { position: 'top' } }
            }
          });

          // 5. Protocol Distribution
          const protocolData = #{JSON.generate(audit_result.rules.group_by(&:protocol).map { |k, v| [k.to_s, v.size] }.to_h)};
          new Chart(document.getElementById('protocolDistributionChart'), {
            type: 'doughnut',
            data: {
              labels: Object.keys(protocolData),
              datasets: [{
                data: Object.values(protocolData),
                backgroundColor: ['#3498db', '#e74c3c', '#f39c12', '#9b59b6']
              }]
            },
            options: {
              responsive: true,
              maintainAspectRatio: false,
              cutout: '60%',
              plugins: { legend: { position: 'bottom' } }
            }
          });

          // 6. Top Ports
          const portCounts = #{JSON.generate(Hash.new(0).tap { |h| audit_result.rules.each { |r| h[r.dport || 'any'] += 1 if r.dport } }.sort_by { |k, v| -v }.take(8).to_h.transform_keys(&:to_s))};
          new Chart(document.getElementById('topPortsChart'), {
            type: 'bar',
            data: {
              labels: Object.keys(portCounts),
              datasets: [{
                label: 'Rule Count',
                data: Object.values(portCounts),
                backgroundColor: '#3498db'
              }]
            },
            options: {
              indexAxis: 'y',
              responsive: true,
              maintainAspectRatio: false,
              scales: { x: { beginAtZero: true } },
              plugins: { title: { display: true, text: 'Top Targeted Ports' } }
            }
          });

          // 7. Simulations
          const totalSimBlocked = #{total_sim_blocked};
          const totalSimAllowed = #{total_sim_allowed};
          new Chart(document.getElementById('simulationsChart'), {
            type: 'pie',
            data: {
              labels: ['Blocked', 'Allowed'],
              datasets: [{
                data: [totalSimBlocked, totalSimAllowed],
                backgroundColor: ['#27ae60', '#e74c3c']
              }]
            },
            options: {
              responsive: true,
              maintainAspectRatio: false
            }
          });

          // 8. Framework Charts
          #{framework_data.map do |data|
            chart_id = data[:name].gsub(/\W+/, '_')
            score = data[:score]
            remaining = (5.0 - score).round(2)
            <<~JS
              new Chart(document.getElementById('#{chart_id}_chart'), {
                type: 'doughnut',
                data: {
                  labels: ['Score', 'Remaining'],
                  datasets: [{
                    data: [#{score}, #{remaining}],
                    backgroundColor: ['#{data[:status] == 'Pass' ? '#27ae60' : '#e74c3c'}', '#ecf0f1']
                  }]
                },
                options: {
                  responsive: true,
                  maintainAspectRatio: false,
                  cutout: '70%',
                  plugins: { legend: { display: false } }
                }
              });
            JS
          end.join("\n")}
        });
      </script>
    </body>
    </html>
  HTML
  
    File.write(html_filename, html_content)
    puts "Interactive HTML report saved to #{html_filename}"
  else
    puts "HTML report not saved."
  end