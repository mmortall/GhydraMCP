package eu.starsong.ghidra.endpoints;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import eu.starsong.ghidra.api.ResponseBuilder;
import eu.starsong.ghidra.util.GhidraSwing;
import eu.starsong.ghidra.util.TransactionHelper;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;

import java.io.IOException;
import java.util.*;

public class MemoryEndpoints extends AbstractEndpoint {

    private static final int DEFAULT_DISASSEMBLY_COUNT = 50;
    private static final int MAX_DISASSEMBLY_SCAN = 256;
    private static final int DEFAULT_MEMORY_LENGTH = 16;
    private static final int MAX_MEMORY_LENGTH = 1048576;
    private PluginTool tool;
    
    public MemoryEndpoints(Program program, int port) {
        super(program, port);
    }
    
    public MemoryEndpoints(Program program, int port, PluginTool tool) {
        super(program, port);
        this.tool = tool;
    }
    
    @Override
    protected PluginTool getTool() {
        return tool;
    }

    @Override
    public void registerEndpoints(HttpServer server) {
        // Per HttpServer docs: paths are matched by longest matching prefix
        // So register specific endpoints first, then more general ones
        
        // Comments endpoint path needs to be registered with a specific context path
        // Example: /memory/0x1000/comments/plate needs a specific handler
        server.createContext("/memory/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            if (path.contains("/comments/")) {
                handleMemoryAddressRequest(exchange);
            } else if (path.equals("/memory/blocks")) {
                handleMemoryBlocksRequest(exchange);
            } else {
                // Handle as general memory address request
                handleMemoryAddressRequest(exchange);
            }
        });
        
        // Register the most general endpoint last
        server.createContext("/memory", this::handleMemoryRequest);
    }
    
    private void handleMemoryRequest(HttpExchange exchange) throws IOException {
        try {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> qparams = parseQueryParams(exchange);
                String addressStr = qparams.get("address");
                if ((addressStr == null || addressStr.isEmpty()) && exchange.getAttribute("address") instanceof String) {
                    addressStr = (String) exchange.getAttribute("address");
                }
                String segmentStr = qparams.get("segment");
                if (segmentStr != null && !segmentStr.isEmpty() && addressStr != null && !addressStr.isEmpty()) {
                    addressStr = segmentStr + "::" + addressStr;
                }
                String lengthStr = qparams.get("length");
                
                // Create ResponseBuilder for HATEOAS-compliant response
                ResponseBuilder builder = new ResponseBuilder(exchange, port)
                    .success(true)
                    .addLink("self", "/memory" + (exchange.getRequestURI().getRawQuery() != null ? 
                        "?" + exchange.getRequestURI().getRawQuery() : ""));
                
                // Add common links
                builder.addLink("program", "/program");
                builder.addLink("blocks", "/memory/blocks");
                
                Program program = getCurrentProgram();
                if (program == null) {
                    sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                    return;
                }
                
                if (addressStr == null || addressStr.isEmpty()) {
                    sendErrorResponse(exchange, 400, "Address parameter is required", "MISSING_PARAMETER");
                    return;
                }
                
                // Parse length parameter
                int length = DEFAULT_MEMORY_LENGTH;
                int requestedLength = length;
                boolean lengthCapped = false;
                if (lengthStr != null && !lengthStr.isEmpty()) {
                    try {
                        length = Integer.decode(lengthStr);
                        requestedLength = length;
                        if (length <= 0) {
                            sendErrorResponse(exchange, 400, "Length must be positive", "INVALID_PARAMETER");
                            return;
                        }
                        if (length > MAX_MEMORY_LENGTH) {
                            Msg.warn(this, "Requested memory read length " + length +
                                     " exceeds maximum " + MAX_MEMORY_LENGTH + ", capping to " + MAX_MEMORY_LENGTH);
                            length = MAX_MEMORY_LENGTH;
                            lengthCapped = true;
                        }
                    } catch (NumberFormatException e) {
                        sendErrorResponse(exchange, 400, "Invalid length parameter", "INVALID_PARAMETER");
                        return;
                    }
                }
                
                // Parse address with overlay-aware resolution.
                Address address = resolveAddress(program, addressStr, true);
                if (address == null) {
                    sendErrorResponse(exchange, 400, "Invalid address format: " + addressStr, "INVALID_ADDRESS");
                    return;
                }
                
                // Read memory
                Memory memory = program.getMemory();
                if (!memory.contains(address)) {
                    sendErrorResponse(exchange, 404,
                        "Address not mapped in memory: " + address.toString(),
                        "ADDRESS_NOT_MAPPED");
                    return;
                }
                
                try {
                    // Read bytes
                    byte[] bytes = new byte[length];
                    int bytesRead = memory.getBytes(address, bytes, 0, length);
                    
                    // Format as hex string (continuous, no spaces - Python bridge parses by pairs)
                    StringBuilder hexString = new StringBuilder();
                    for (int i = 0; i < bytesRead; i++) {
                        String hex = Integer.toHexString(bytes[i] & 0xFF).toUpperCase();
                        if (hex.length() == 1) {
                            hexString.append('0');
                        }
                        hexString.append(hex);
                    }
                    
                    // Build result object
                    Map<String, Object> result = new HashMap<>();
                    result.put("address", address.toString());
                    result.put("bytesRead", bytesRead);
                    result.put("hexBytes", hexString.toString());
                    result.put("rawBytes", Base64.getEncoder().encodeToString(bytes));
                    if (lengthCapped) {
                        result.put("warning", "Requested length " + requestedLength +
                                   " exceeds maximum " + MAX_MEMORY_LENGTH + "; result was capped");
                    }
                    
                    // Add next/prev links
                    builder.addLink("next", "/memory?address=" + address.add(length) + "&length=" + length);
                    if (address.getOffset() >= length) {
                        builder.addLink("prev", "/memory?address=" + address.subtract(length) + "&length=" + length);
                    }
                    
                    // Add result and send response
                    builder.result(result);
                    sendJsonResponse(exchange, builder.build(), 200);
                    
                } catch (MemoryAccessException e) {
                    sendErrorResponse(exchange, 404, "Cannot read memory at address: " + e.getMessage(), "MEMORY_ACCESS_ERROR");
                }
                
            } else {
                sendErrorResponse(exchange, 405, "Method Not Allowed");
            }
        } catch (Exception e) {
            Msg.error(this, "Error in /memory endpoint", e);
            sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
        }
    }
    
    /**
 * Handle requests to /memory/{address} including child resources like comments
 */
private void handleMemoryAddressRequest(HttpExchange exchange) throws IOException {
    try {
        // Extract address from path: /memory/{address}/...
        String path = exchange.getRequestURI().getPath();
        if (path.equals("/memory/") || path.equals("/memory")) {
            handleMemoryRequest(exchange);
            return;
        }
        
        // Parse address from path
        String remainingPath = path.substring("/memory/".length());
        
        // Check if this is a request for a specific address's comments
        if (remainingPath.contains("/comments/")) {
            // Format: /memory/{address}/comments/{comment_type}
            String[] parts = remainingPath.split("/comments/", 2);
            String addressStr = parts[0];
            String commentType = parts.length > 1 ? parts[1] : "plate"; // Default to plate comments

            handleMemoryComments(exchange, addressStr, commentType);
            return;
        }

        // Check if this is a disassembly request
        if (remainingPath.contains("/disassembly")) {
            String addressStr = remainingPath.split("/disassembly")[0];
            handleDisassemblyAtAddress(exchange, addressStr);
            return;
        }
        
        // Otherwise, treat as a direct memory request with address in the path
        String addressStr = remainingPath;
        Map<String, String> params = parseQueryParams(exchange);
        
        // Handle same as the query parameter version
        params.put("address", addressStr);
        exchange.setAttribute("address", addressStr);
        
        // Delegate to the main memory handler
        handleMemoryRequest(exchange);
    } catch (Exception e) {
        Msg.error(this, "Error handling memory address endpoint", e);
        sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR");
    }
}

/**
 * Handle requests to set or get comments at a specific memory address
 */
private void handleMemoryComments(HttpExchange exchange, String addressStr, String commentType) throws IOException {
    try {
        String method = exchange.getRequestMethod();
        Program program = getCurrentProgram();
        
        if (program == null) {
            sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
            return;
        }
        
        // Parse address
        Address address;
        address = resolveAddress(program, addressStr, true);
        if (address == null) {
            sendErrorResponse(exchange, 400, "Invalid address format: " + addressStr, "INVALID_ADDRESS");
            return;
        }
        
        // Validate comment type
        if (!isValidCommentType(commentType)) {
            sendErrorResponse(exchange, 400, "Invalid comment type: " + commentType, "INVALID_COMMENT_TYPE");
            return;
        }
                
        if ("GET".equals(method)) {
            // Get existing comment
            String comment = getCommentByType(program, address, commentType);
            
            Map<String, Object> result = new HashMap<>();
            result.put("address", addressStr);
            result.put("comment_type", commentType);
            result.put("comment", comment != null ? comment : "");
            
            ResponseBuilder builder = new ResponseBuilder(exchange, port)
                .success(true)
                .result(result)
                .addLink("self", "/memory/" + addressStr + "/comments/" + commentType);
                
            sendJsonResponse(exchange, builder.build(), 200);
            
        } else if ("POST".equals(method)) {
            // Set comment
            Map<String, String> params = parseJsonPostParams(exchange);
            String comment = params.get("comment");
            
            if (comment == null) {
                sendErrorResponse(exchange, 400, "Comment parameter is required", "MISSING_PARAMETER");
                return;
            }
            
            boolean success = setCommentByType(program, address, commentType, comment);
            
            if (success) {
                Map<String, Object> result = new HashMap<>();
                result.put("address", addressStr);
                result.put("comment_type", commentType);
                result.put("comment", comment);
                
                ResponseBuilder builder = new ResponseBuilder(exchange, port)
                    .success(true)
                    .result(result)
                    .addLink("self", "/memory/" + addressStr + "/comments/" + commentType);
                    
                sendJsonResponse(exchange, builder.build(), 200);
            } else {
                sendErrorResponse(exchange, 500, "Failed to set comment", "COMMENT_SET_FAILED");
            }
        } else {
            sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
        }
    } catch (Exception e) {
        Msg.error(this, "Error handling memory comments", e);
        sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR");
    }
}

/**
 * Check if the comment type is valid
 */
private boolean isValidCommentType(String commentType) {
    return commentType.equals("plate") || 
           commentType.equals("pre") || 
           commentType.equals("post") || 
           commentType.equals("eol") ||
           commentType.equals("repeatable");
}

/**
 * Get a comment by type at the specified address
 */
private String getCommentByType(Program program, Address address, String commentType) {
    if (program == null) return null;

    CommentType type = getCommentType(commentType);
    return program.getListing().getComment(type, address);
}

/**
 * Set a comment by type at the specified address
 */
private boolean setCommentByType(Program program, Address address, String commentType, String comment) {
    if (program == null) return false;

    CommentType type = getCommentType(commentType);

    try {
        return TransactionHelper.executeInTransaction(program, "Set " + commentType + " comment at " + address, () -> {
            program.getListing().setComment(address, type, comment);
            return true;
        });
    } catch (Exception e) {
        Msg.error(this, "Error setting comment", e);
        return false;
    }
}

/**
 * Convert comment type string to Ghidra's CommentType enum
 */
private CommentType getCommentType(String commentType) {
    switch (commentType.toLowerCase()) {
        case "plate":
            return CommentType.PLATE;
        case "pre":
            return CommentType.PRE;
        case "post":
            return CommentType.POST;
        case "eol":
            return CommentType.EOL;
        case "repeatable":
            return CommentType.REPEATABLE;
        default:
            return CommentType.PLATE;
    }
}

private static int parseDisassemblyInteger(String value, int fallback) {
        return value == null ? fallback : Integer.parseInt(value.trim());
    }

    private void handleDisassemblyAtAddress(HttpExchange exchange, String addressStr) throws IOException {
        try {
            if (!"GET".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "Method Not Allowed");
                return;
            }
            Program program = getCurrentProgram();
            if (program == null) {
                sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                return;
            }
            Map<String, String> params = parseQueryParams(exchange);
            String limitStr = params.get("limit") != null ? params.get("limit") : params.get("count");
            final int count;
            final int offset;
            try {
                count = parseDisassemblyInteger(limitStr, DEFAULT_DISASSEMBLY_COUNT);
                offset = parseDisassemblyInteger(params.get("offset"), 0);
            } catch (NumberFormatException error) {
                sendErrorResponse(exchange, 400, "Count and offset must be integers", "INVALID_RANGE");
                return;
            }
            if (count <= 0 || offset < 0) {
                sendErrorResponse(exchange, 400,
                    "Count must be positive and offset must be non-negative", "INVALID_RANGE");
                return;
            }
            if ((long) count + offset > MAX_DISASSEMBLY_SCAN) {
                sendErrorResponse(exchange, 400,
                    "Count plus offset exceeds maximum disassembly scan", "INVALID_RANGE");
                return;
            }
            Address startAddr = resolveAddress(program, addressStr, true);
            if (startAddr == null) {
                sendErrorResponse(exchange, 400, "Invalid address: " + addressStr, "INVALID_ADDRESS");
                return;
            }
            final Program prog = program;
            final Address[] nextAddress = new Address[] {startAddr};
            final boolean[] decodeComplete = new boolean[] {true};
            final String[] decodeError = new String[] {null};
            final List<Map<String, Object>> allInstructions = new ArrayList<>();
            GhidraSwing.runRead(() -> {
                PseudoDisassembler disassembler = new PseudoDisassembler(prog);
                disassembler.setRespectExecuteFlag(false);
                Memory memory = prog.getMemory();
                Address instructionAddress = startAddr;
                for (int scanned = 0; scanned < offset + count; scanned++) {
                    nextAddress[0] = instructionAddress;
                    try {
                        PseudoInstruction instr = disassembler.disassemble(instructionAddress);
                        if (instr == null) {
                            decodeComplete[0] = false;
                            decodeError[0] = "No instruction decoded at " + instructionAddress;
                            break;
                        }
                        int parsedLength = instr.getParsedLength();
                        if (parsedLength <= 0) {
                            decodeComplete[0] = false;
                            decodeError[0] = "Invalid instruction length at " + instructionAddress;
                            break;
                        }
                        byte[] bytes = new byte[parsedLength];
                        if (memory.getBytes(instructionAddress, bytes) != parsedLength) {
                            throw new IOException("Incomplete instruction bytes at " + instructionAddress);
                        }
                        if (scanned >= offset) {
                            StringBuilder hexBytes = new StringBuilder();
                            for (byte value : bytes) {
                                hexBytes.append(String.format("%02X", value & 0xFF));
                            }
                            Map<String, Object> row = new HashMap<>();
                            row.put("address", instructionAddress.toString());
                            row.put("bytes", hexBytes.toString());
                            row.put("mnemonic", instr.getMnemonicString());
                            row.put("operands", instr.toString().substring(instr.getMnemonicString().length()).trim());
                            allInstructions.add(row);
                        }
                        instructionAddress = instructionAddress.add(parsedLength);
                        nextAddress[0] = instructionAddress;
                    } catch (Exception error) {
                        decodeComplete[0] = false;
                        decodeError[0] = "Decode failed at " + instructionAddress + ": " + error.getMessage();
                        break;
                    }
                }
                return null;
            });
            Map<String, Object> result = new HashMap<>();
            result.put("startAddress", addressStr);
            result.put("instructions", allInstructions);
            result.put("totalInstructions", allInstructions.size());
            result.put("disassemblyMode", "pseudo");
            result.put("decodeComplete", decodeComplete[0]);
            if (decodeError[0] != null) {
                result.put("decodeError", decodeError[0]);
            }
            String selfHref = "/memory/" + addressStr + "/disassembly?count=" + count;
            if (offset != 0) {
                selfHref += "&offset=" + offset;
            }
            ResponseBuilder builder = new ResponseBuilder(exchange, port)
                .success(true).result(result).addLink("self", selfHref);
            if (!allInstructions.isEmpty() && decodeComplete[0]) {
                builder.addLink("next", "/memory/" + nextAddress[0].toString() + "/disassembly?count=" + count);
            }
            sendJsonResponse(exchange, builder.build(), 200);
        } catch (Exception error) {
            Msg.error(this, "Error in disassembly at address endpoint", error);
            sendErrorResponse(exchange, 500, "Internal server error: " + error.getMessage(), "INTERNAL_ERROR");
        }
    }

    private void handleMemoryBlocksRequest(HttpExchange exchange) throws IOException {
        try {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> qparams = parseQueryParams(exchange);
                int offset = parseIntOrDefault(qparams.get("offset"), 0);
                int limit = parseIntOrDefault(qparams.get("limit"), 100);
                
                Program program = getCurrentProgram();
                if (program == null) {
                    sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                    return;
                }
                
                // Create ResponseBuilder for HATEOAS-compliant response
                ResponseBuilder builder = new ResponseBuilder(exchange, port)
                    .success(true)
                    .addLink("self", "/memory/blocks" + (exchange.getRequestURI().getRawQuery() != null ? 
                        "?" + exchange.getRequestURI().getRawQuery() : ""));
                
                // Add common links
                builder.addLink("program", "/program");
                builder.addLink("memory", "/memory");
                
                // Get memory blocks
                final Memory memory = program.getMemory();
                final List<Map<String, Object>> blocks = new ArrayList<>();

                GhidraSwing.runRead(() -> {
                    for (MemoryBlock block : memory.getBlocks()) {
                        Map<String, Object> blockInfo = new HashMap<>();
                        blockInfo.put("name", block.getName());
                        blockInfo.put("start", block.getStart().toString());
                        blockInfo.put("end", block.getEnd().toString());
                        blockInfo.put("size", block.getSize());
                        blockInfo.put("permissions", getPermissionString(block));
                        blockInfo.put("isInitialized", block.isInitialized());
                        blockInfo.put("isLoaded", block.isLoaded());
                        blockInfo.put("isMapped", block.isMapped());
                        blocks.add(blockInfo);
                    }
                });
                
                // Apply pagination and add it to result
                List<Map<String, Object>> paginatedBlocks = 
                    applyPagination(blocks, offset, limit, builder, "/memory/blocks");
                
                // Add the result to the builder
                builder.result(paginatedBlocks);
                
                // Send the HATEOAS-compliant response
                sendJsonResponse(exchange, builder.build(), 200);
                
            } else {
                sendErrorResponse(exchange, 405, "Method Not Allowed");
            }
        } catch (Exception e) {
            Msg.error(this, "Error in /memory/blocks endpoint", e);
            sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
        }
    }
    
    private String getPermissionString(MemoryBlock block) {
        StringBuilder perms = new StringBuilder();
        perms.append(block.isRead() ? "r" : "-");
        perms.append(block.isWrite() ? "w" : "-");
        perms.append(block.isExecute() ? "x" : "-");
        perms.append(block.isVolatile() ? "v" : "-");
        return perms.toString();
    }
}
