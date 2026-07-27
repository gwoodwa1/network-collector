. as $source
| (if ((.input_errors // 0) > $params.error_threshold)
       or ((.crc_errors // 0) > $params.error_threshold)
       or ((.output_errors // 0) > $params.error_threshold)
   then [{
     "rule": "interface-errors",
     "severity": "warning",
     "message": "Interface errors detected",
     "evidence": {
       "input_errors": (.input_errors // 0),
       "crc_errors": (.crc_errors // 0),
       "output_errors": (.output_errors // 0)
     }
   }]
   else []
   end) as $issues
| $source + {
    "_summary": {
      "has_issues": (($issues | length) > 0),
      "issue_count": ($issues | length),
      "issues": $issues
    }
  }
