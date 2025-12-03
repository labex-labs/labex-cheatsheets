/**
 * Fix BaseQuiz Code Formatting Script
 *
 * This script processes all markdown files in the docs/cheatsheets directory
 * and replaces backtick-wrapped code within BaseQuiz components with <code> tags.
 *
 * Usage:
 *   npx esno scripts/fix-basequiz-code.ts
 *
 * What it does:
 *   - Scans all .md files in docs/cheatsheets/ recursively
 *   - Finds BaseQuiz components in each file
 *   - Replaces backtick code (e.g., `git commit -m "message"`) with <code> tags
 *     (e.g., <code>git commit -m "message"</code>) inside BaseQuiz components only
 *   - Preserves all other content unchanged
 *
 * Example transformation:
 *   Before: What does `git commit -m "message"` do?
 *   After:  What does <code>git commit -m "message"</code> do?
 *
 * Note: This script only modifies code formatting within BaseQuiz components.
 * Regular markdown code blocks and inline code outside BaseQuiz are not affected.
 */

import { readFileSync, writeFileSync, readdirSync, statSync } from 'fs'
import path from 'path'

/**
 * Replace backtick-wrapped code with <code> tags inside BaseQuiz components
 *
 * @param content - The file content to process
 * @returns The modified content with backticks replaced by <code> tags
 *
 * Example: `git commit -m "message"` -> <code>git commit -m "message"</code>
 */
function replaceBackticksInBaseQuiz(content: string): string {
  // Match complete BaseQuiz blocks (including opening and closing tags)
  // Use [\s\S] to match all characters including newlines
  const baseQuizRegex = /(<BaseQuiz[^>]*>[\s\S]*?<\/BaseQuiz>)/g

  return content.replace(baseQuizRegex, (match) => {
    // Inside BaseQuiz blocks, replace backtick-wrapped code with <code> tags
    // Match backtick-wrapped content, supporting quotes inside
    // Use non-greedy matching to avoid cross-line issues
    return match.replace(/`([^`\n]+)`/g, '<code>$1</code>')
  })
}

/**
 * Process a single markdown file
 *
 * @param filePath - Path to the markdown file to process
 * @returns true if the file was modified, false otherwise
 */
function processFile(filePath: string): boolean {
  try {
    const content = readFileSync(filePath, 'utf-8')

    // Skip files that don't contain BaseQuiz components
    if (!content.includes('<BaseQuiz')) {
      return false
    }

    const modifiedContent = replaceBackticksInBaseQuiz(content)

    if (modifiedContent !== content) {
      writeFileSync(filePath, modifiedContent, 'utf-8')
      return true
    }

    return false
  } catch (error) {
    console.error(`Error processing ${filePath}:`, error)
    return false
  }
}

/**
 * Recursively find all .md files in a directory
 *
 * @param dir - Directory to search
 * @param fileList - Accumulator array for found files
 * @returns Array of all markdown file paths
 */
function findMdFiles(dir: string, fileList: string[] = []): string[] {
  const files = readdirSync(dir)

  for (const file of files) {
    const filePath = path.join(dir, file)
    const stat = statSync(filePath)

    if (stat.isDirectory()) {
      findMdFiles(filePath, fileList)
    } else if (file.endsWith('.md')) {
      fileList.push(filePath)
    }
  }

  return fileList
}

/**
 * Main function to process all markdown files
 */
function main() {
  const docsDir = path.join(process.cwd(), 'docs', 'cheatsheets')
  const mdFiles = findMdFiles(docsDir)

  console.log(`Found ${mdFiles.length} markdown files`)

  let processedCount = 0
  let modifiedCount = 0

  mdFiles.forEach(filePath => {
    processedCount++
    if (processFile(filePath)) {
      modifiedCount++
      console.log(`Modified: ${path.relative(process.cwd(), filePath)}`)
    }
  })

  console.log(`\nProcessed ${processedCount} files`)
  console.log(`Modified ${modifiedCount} files`)
}

main()

