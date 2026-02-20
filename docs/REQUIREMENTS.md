# Introduction
A sanctum is a latin word to describe a "holy place" or "That which is holy". This Sanctum is a basic text logger, a simple journal where a user creates a document, and edits text.

# Functional Requirements
- The reflection to be stored is a text file
- The system must encrypt the reflections of the user ensuring only the user is able to see it's contents
- There is no need for users/auth the only user will be the owner of the system
- The files must be organized by days, the user can submit multiples reflections per day

# Non-Functional Requirements
- Latency < 50ms
- 99.9% Availability
- 100% Unit Test Coverage
- Envelope encryption, with metadata columns to allow sql query
