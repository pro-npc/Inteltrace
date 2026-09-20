import type { ParsedSources } from './csv';

export interface AIEnrichedData {
  correlations: {
    pair: string;
    title: string;
    confidence: number;
    risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    finding: string;
    action: string;
  }[];
  riskBreakdown: { label: string; points: number }[];
  nodeFacts: Record<string, string[]>;
  networkEdgeLabels: Record<string, string>; // key: "from_to" -> label
}

export async function runAIForensicAnalysis(
  parsed: ParsedSources,
  apiKey: string | undefined,
  baseUrl: string | undefined,
  primaryModel: string,
  validatorModel: string
): Promise<AIEnrichedData | null> {
  if (!apiKey || !baseUrl) return null;

  // 1. Aggregate Data to save context window
  const cdrSummary = parsed.cdr.length > 0
    ? `CDR Data: ${parsed.cdr.length} total calls.`
    : 'CDR Data: None.';
  
  const ipdrSummary = parsed.ipdr.length > 0
    ? `IPDR Data: ${parsed.ipdr.length} sessions. Domains accessed include ${Array.from(new Set(parsed.ipdr.map(s => s.domain))).slice(0, 10).join(', ')}.`
    : 'IPDR Data: None.';

  const bankSummary = parsed.bank.length > 0
    ? `Bank Data: ${parsed.bank.length} transactions. Total volume: ${parsed.bank.reduce((sum, b) => sum + Number(b.amount || 0), 0)}.`
    : 'Bank Data: None.';

  const socialSummary = parsed.social.length > 0
    ? `Social Data: ${parsed.social.length} posts.`
    : 'Social Data: None.';

  const payload = {
    model: primaryModel,
    messages: [
      {
        role: "system",
        content: `You are an expert cyber-forensic AI engine. Your job is to extract intelligence from raw telemetry.
You will be provided with aggregated data summaries.
You must return a strictly formatted JSON object with the following schema:
{
  "correlations": [ { "pair": "CDR ↔ Bank", "title": "...", "confidence": 90, "risk": "CRITICAL|HIGH|MEDIUM|LOW", "finding": "...", "action": "..." } ],
  "riskBreakdown": [ { "label": "Large Transactions", "points": 25 } ],
  "nodeFacts": { "node_name_or_number": ["Fact 1", "Fact 2"] },
  "networkEdgeLabels": { "from_to": "15 calls" }
}
Do not hallucinate. If there is not enough data, return empty arrays. Only use the data provided.`
      },
      {
        role: "user",
        content: `${cdrSummary}\n${ipdrSummary}\n${bankSummary}\n${socialSummary}`
      }
    ],
    response_format: { type: "json_object" }
  };

  try {
    const res = await fetch(`${baseUrl.replace(/\/$/, '')}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`
      },
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      console.error('OmniRoute API Error:', await res.text());
      return null;
    }

    const data = await res.json();
    const content = data.choices?.[0]?.message?.content;
    if (!content) return null;

    let parsedJson: AIEnrichedData;
    try {
      parsedJson = JSON.parse(content);
    } catch (e) {
      console.error('Failed to parse AI JSON:', content);
      return null;
    }

    // Tier 2: Validation Pass (Fast fact-check)
    const valPayload = {
      model: validatorModel,
      messages: [
        {
          role: "system",
          content: "You are a fact-checker. Verify if the following findings logically align with the aggregated data summary provided. Return a JSON object: { \"valid\": true } if they are reasonable, or { \"valid\": false } if they hallucinate specific transactions or numbers not present."
        },
        {
          role: "user",
          content: `Summary: ${cdrSummary}\n${ipdrSummary}\n${bankSummary}\n${socialSummary}\n\nFindings: ${content}`
        }
      ],
      response_format: { type: "json_object" }
    };

    const valRes = await fetch(`${baseUrl.replace(/\/$/, '')}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`
      },
      body: JSON.stringify(valPayload)
    });

    if (valRes.ok) {
      const valData = await valRes.json();
      const valContent = valData.choices?.[0]?.message?.content;
      try {
        const valJson = JSON.parse(valContent);
        if (valJson.valid === false) {
          console.warn('AI Validator rejected the findings. Falling back to heuristic.');
          return null; // Reject hallucinated data
        }
      } catch (e) {}
    }

    return parsedJson;
  } catch (error) {
    console.error('OmniRoute Fetch Exception:', error);
    return null;
  }
}
