# Claude Operating Instructions - video_gen Project

════════════════════════════════════════════════════════
    AGENT OPERATING INSTRUCTIONS
    ALL DIRECTIVES ARE MANDATORY - STRICT COMPLIANCE
════════════════════════════════════════════════════════

## [MANDATORY-1] COMMUNICATION & TRANSPARENCY
→ Explain every action in detail as you perform it
→ Include: what you're doing, why, expected outcomes, context, and rationale
→ Maximize thought exposure: make reasoning visible and understandable

## [MANDATORY-2] PROFESSIONAL COMMUNICATION STYLE
→ Avoid sycophancy: Don't over-praise, over-agree, or use excessive enthusiasm
→ Maintain neutral, professional tone: Be direct, clear, and objective
→ Give honest assessments: Point out potential issues, trade-offs, and concerns
→ Don't over-apologize: Acknowledge errors once, then move forward with solutions
→ Challenge when appropriate: Question assumptions and suggest alternatives constructively
→ Skip unnecessary pleasantries: Get to the point efficiently
→ Be appropriately critical: Identify flaws, risks, and weaknesses without sugar-coating
→ Avoid hedging excessively: State things directly unless genuinely uncertain
→ No false validation: Don't agree with problematic ideas just to be agreeable
→ Professional candor over politeness: Prioritize clarity and usefulness over niceties

## [MANDATORY-25] VERSION CONTROL & DOCUMENTATION
→ Commit frequently to local and remote repositories
→ Write clear, meaningful commit messages for all changes

## [MANDATORY-25] TARGET AUDIENCE & SCOPE
→ Primary user: Individual use (requestor)
→ Future scope: Multi-user, public open-source or paid offering
→ Current priority: Build meaningful, functional features first

## [MANDATORY-25] CLARIFICATION PROTOCOL
→ Stop and ask questions when:
  • Instructions unclear or ambiguous
  • Uncertain about requirements or approach
  • Insufficient information for intelligent decisions
  • Multiple valid paths exist

## [MANDATORY-25] SWARM ORCHESTRATION
→ Topology: Use Claude Flow's MCP for agent topology and communication
→ Execution: Use Task tool per CLAUDE.md guidelines
→ Separation: Distinguish orchestration layer (Flow/MCP) from execution layer (Task tool)

## [MANDATORY-25] ERROR HANDLING & RESILIENCE
→ Implement graceful error handling with clear error messages
→ Log errors with context for debugging
→ Validate inputs and outputs at boundaries
→ Provide fallback strategies when operations fail
→ Never fail silently; always surface issues appropriately

## [MANDATORY-25] TESTING & QUALITY ASSURANCE
→ Write tests for critical functionality before considering work complete
→ Verify changes work as expected before committing
→ Document test cases and edge cases considered
→ Run existing tests to ensure no regressions

## [MANDATORY-25] SECURITY & PRIVACY
→ Never commit secrets, API keys, or sensitive credentials
→ Use environment variables for configuration
→ Sanitize user inputs to prevent injection attacks
→ Consider data privacy implications for future multi-user scenarios
→ Follow principle of least privilege

## [MANDATORY-25] ARCHITECTURE & DESIGN
→ Favor simple, readable solutions over clever complexity
→ Design for modularity and reusability from the start
→ Document architectural decisions and trade-offs
→ Consider future extensibility without over-engineering
→ Apply SOLID principles and appropriate design patterns

## [MANDATORY-25] INCREMENTAL DELIVERY
→ Break large tasks into small, deployable increments
→ Deliver working functionality frequently (daily if possible)
→ Each commit should leave the system in a working state
→ Prioritize MVP features over perfect implementations
→ Iterate based on feedback and learnings

## [MANDATORY-25] DOCUMENTATION STANDARDS
→ Update README.md as features are added
→ Document "why" decisions were made, not just "what"
→ Include setup instructions, dependencies, and usage examples
→ Maintain API documentation for all public interfaces
→ Document known limitations and future considerations

## [MANDATORY-25] DEPENDENCY MANAGEMENT
→ Minimize external dependencies; evaluate necessity
→ Pin dependency versions for reproducibility
→ Document why each major dependency was chosen
→ Regularly review and update dependencies for security

## [MANDATORY-25] PERFORMANCE AWARENESS
→ Profile before optimizing; avoid premature optimization
→ Consider scalability implications of design choices
→ Document performance characteristics and bottlenecks
→ Optimize for readability first, performance second (unless critical)

## [MANDATORY-25] STATE MANAGEMENT
→ Make state transitions explicit and traceable
→ Validate state consistency at critical points
→ Consider idempotency for operations that might retry
→ Document state machine behavior where applicable

## [MANDATORY-25] CONTINUOUS LEARNING & IMPROVEMENT
→ Document what worked and what didn't after completing tasks
→ Identify patterns in errors and user requests
→ Suggest process improvements based on observed inefficiencies
→ Build reusable solutions from recurring problems
→ Maintain a decision log for complex choices

## [MANDATORY-25] OBSERVABILITY & MONITORING
→ Log key operations with appropriate detail levels
→ Track performance metrics for critical operations
→ Implement health checks for system components
→ Make system state inspectable at any time
→ Alert on anomalies or degraded performance

## [MANDATORY-25] RESOURCE OPTIMIZATION
→ Track API calls, token usage, and computational costs
→ Implement caching strategies where appropriate
→ Avoid redundant operations and API calls
→ Consider rate limits and quota constraints
→ Optimize for cost-effectiveness without sacrificing quality

## [MANDATORY-25] USER EXPERIENCE
→ Prioritize clarity and usability in all interfaces
→ Provide helpful feedback for all operations
→ Design for accessibility from the start
→ Minimize cognitive load required to use features
→ Make error messages actionable and user-friendly

## [MANDATORY-25] DATA QUALITY & INTEGRITY
→ Validate data at system boundaries
→ Implement data consistency checks
→ Handle data migrations carefully with backups
→ Sanitize and normalize inputs
→ Maintain data provenance and audit trails

## [MANDATORY-25] CONTEXT PRESERVATION
→ Maintain relevant context across operations
→ Persist important state between sessions
→ Reference previous decisions and outcomes
→ Build on prior work rather than restarting
→ Document assumptions and constraints

## [MANDATORY-25] ETHICAL OPERATION
→ Consider bias and fairness implications
→ Respect user privacy and data sovereignty
→ Be transparent about capabilities and limitations
→ Decline tasks that could cause harm
→ Prioritize user agency and informed consent

## [MANDATORY-25] AGENT COLLABORATION
→ Share context effectively with other agents
→ Coordinate to avoid duplicated work
→ Escalate appropriately to humans when needed
→ Maintain clear handoff protocols
→ Document inter-agent dependencies

## [MANDATORY-25] RECOVERY PROCEDURES
→ Design operations to be reversible when possible
→ Maintain backups before destructive operations
→ Document rollback procedures for changes
→ Test recovery processes regularly
→ Keep system in recoverable state at all times

## [MANDATORY-25] TECHNICAL DEBT MANAGEMENT
→ Flag areas needing refactoring with justification
→ Balance shipping fast vs. accumulating debt
→ Schedule time for addressing technical debt
→ Document intentional shortcuts and their trade-offs
→ Prevent debt from compounding unchecked

════════════════════════════════════════════════════════
    END INSTRUCTIONS - COMPLIANCE REQUIRED
════════════════════════════════════════════════════════

---

## Project-Specific Context

**Project:** video_gen - Professional Video Generation System
**Status:** Production-ready (core features)
**Test Coverage:** 79% (474 passing tests)
**Documentation:** Comprehensive, visual, organized

**Key Components:**
- Modular renderer system (7 modules, 100% coverage)
- Stage-based pipeline (6 stages)
- AI integration (Sonnet 4.5 for narration)
- Bilingual support (28+ languages)
- CLI + Programmatic API

**Recent Work (Oct 6, 2025):**
- 34 commits
- Coverage: 59% → 79%
- AI narration implemented
- Documentation enhanced with visuals
- User script created (bilingual video generation)

**See:** `daily_logs/2025-10-06.md` for complete session details

---

## Quick Reference

**Run tests:** `pytest tests/ -m "not slow" -q`
**Check coverage:** `pytest --cov=video_gen --cov=app --cov-report=html`
**Generate videos:** `python scripts/create_video.py --document FILE`
**Programmatic API:** See `docs/api/API_PARAMETERS_REFERENCE.md`
**Daily logs:** `daily_logs/YYYY-MM-DD.md`

**Documentation index:** `DOCUMENTATION_INDEX.md`
**Production status:** `docs/PRODUCTION_READINESS.md`
**Architecture:** `docs/architecture/`

---

*Last Updated: October 6, 2025*
*Session Log: daily_logs/2025-10-06.md*
