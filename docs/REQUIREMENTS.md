# Introduction
A sanctum is a latin word to describe a "holy place" or "That which is holy". This Sanctum is a basic text editor, a simple journal where a user creates a document, edits text, see the rendered markdown and can restore to earlier versions.

# Functional Requirements
- The reflection to be stored is a markdown file
- The system must allow the user to register and login
- The system must encrypt the reflections of the user ensuring only the user is able to see it's contents
- The system must allow the user to see the preview of the rendered markdown file
- User must be able to create and edit folders and documents
- The system must have a version history
- Only the author can read the notes that were written
- We must have the idea of "day" and the user can submit multiple reflections per day.

# Non-Functional Requirements
- Latency < 100ms
- 99.9% Availability
- 100% Unit Test Coverage
- Not sure about encrypting I know nothing about this
