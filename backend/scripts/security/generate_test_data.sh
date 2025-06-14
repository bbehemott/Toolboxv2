#!/bin/bash
echo "🧪 GÉNÉRATION DE DONNÉES TEST POUR DASHBOARD SÉCURITÉ"
echo "====================================================="

# Test connectivité GELF
echo "🔍 Test connectivité GELF..."
if ! nc -zv localhost 12201 2>/dev/null; then
    echo "❌ Port GELF 12201 non accessible"
    exit 1
fi
echo "✅ GELF accessible"

# Génération d'attaques Brute Force
echo "🔴 Génération attaques Brute Force..."
for i in {1..10}; do
    ip="203.0.113.$((i % 20 + 1))"
    echo "{\"version\":\"1.1\",\"host\":\"security-test\",\"short_message\":\"brute force attack from $ip attempt #$i\",\"level\":4,\"source_ip\":\"$ip\",\"attack_type\":\"brute_force\"}" | nc -u localhost 12201
    echo "  ├── Brute force $i/10 depuis $ip"
    sleep 1
done

# Génération de scans de ports
echo "🟠 Génération scans de ports..."
for i in {1..8}; do
    ip="198.51.100.$((i % 15 + 1))"
    echo "{\"version\":\"1.1\",\"host\":\"security-test\",\"short_message\":\"nmap port scan from $ip on port $((i*100))\",\"level\":4,\"source_ip\":\"$ip\",\"attack_type\":\"port_scan\"}" | nc -u localhost 12201
    echo "  ├── Port scan $i/8 depuis $ip"
    sleep 1
done

# Génération d'attaques web
echo "🟡 Génération attaques web..."
for i in {1..6}; do
    ip="192.0.2.$((i % 12 + 1))"
    echo "{\"version\":\"1.1\",\"host\":\"security-test\",\"short_message\":\"sql injection attack from $ip\",\"level\":5,\"source_ip\":\"$ip\",\"attack_type\":\"web_attack\"}" | nc -u localhost 12201
    echo "  ├── Web attack $i/6 depuis $ip"
    sleep 1
done

echo "⏳ Attente indexation (30s)..."
sleep 30

# Vérification
echo "🔍 Vérification dans Graylog..."
total=$(curl -s -u admin:admin -H "X-Requested-By: test" \
  "http://localhost:9000/api/search/universal/relative?query=security-test&range=300" | \
  grep -o '"total_results":[0-9]*' | cut -d: -f2)

echo "✅ $total messages générés dans Graylog"
